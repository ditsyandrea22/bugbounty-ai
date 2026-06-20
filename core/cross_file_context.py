"""
core/cross_file_context.py

Membangun konteks lintas file untuk disuntikkan ke VulnerabilityHunter.

MASALAH YANG DIPECAHKAN:
Pipeline sebelumnya menganalisis tiap evidence secara terisolasi -- GPT
hanya melihat snippet kode di sekitar lokasi temuan, tanpa tahu:
- Siapa yang memanggil fungsi ini (caller graph)
- Library/contract apa yang diimport
- Bagaimana data mengalir dari input user ke titik bug

Ini berarti kelas bug yang paling menarik untuk bug bounty (multi-step,
lintas file) tidak terdeteksi:
- Privilege escalation via role confusion antar modul
- Reentrancy yang butuh dua kontrak untuk dieksploitasi
- Data flow dari input user yang melewati beberapa fungsi sebelum
  mencapai titik eksekusi berbahaya

PENDEKATAN (heuristik berbasis teks, bukan AST penuh):
Untuk setiap file yang mengandung finding, kita:
1. Ekstrak semua import/mengimport statements
2. Cari file-file yang diimport di repo dan baca bagian kritis-nya
3. Buat ringkasan "who calls what" sederhana berbasis pattern matching
4. Suntikkan sebagai context tambahan ke prompt GPT

Ini bukan call graph yang akurat (untuk itu butuh tree-sitter -- lihat
roadmap), tapi sudah jauh lebih baik dari tidak ada sama sekali.
"""

from __future__ import annotations

import re
from pathlib import Path

IMPORT_PATTERNS = {
    "python": [
        r"^from\s+([\w.]+)\s+import",
        r"^import\s+([\w.]+)",
    ],
    "javascript": [
        r"(?:import|require)\s*\(?['\"]([^'\"]+)['\"]",
    ],
    "typescript": [
        r"(?:import|require)\s*\(?['\"]([^'\"]+)['\"]",
    ],
    "solidity": [
        r'import\s+["\']([^"\']+)["\']',
        r"import\s+\{[^}]+\}\s+from\s+['\"]([^'\"]+)['\"]",
    ],
}

CRITICAL_FUNCTION_PATTERNS = {
    "python": [
        r"def\s+(check_\w+|verify_\w+|validate_\w+|authenticate\w*|authorize\w*|require_\w+)\s*\(",
        r"def\s+(transfer|withdraw|deposit|approve|execute)\s*\(",
    ],
    "solidity": [
        r"function\s+(transfer|withdraw|deposit|approve|execute|onlyOwner|mint|burn)\s*\(",
        r"modifier\s+(\w+)\s*\(",
    ],
}


class CrossFileContext:
    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)
        self._file_cache: dict[str, str] = {}

    def build_context_for_file(
        self,
        target_file: str,
        language: str,
        max_context_chars: int = 3000,
    ) -> str:
        """
        Membangun context lintas file untuk satu file yang mengandung finding.

        Returns string yang siap disuntikkan ke prompt GPT, berisi:
        - Daftar file yang diimport dan fungsi kritis yang ada di dalamnya
        - Warning kalau ada import dari file yang mengandung pola berbahaya
        """
        target_path = Path(target_file)
        if not target_path.is_absolute():
            target_path = self.repo_root / target_file

        if not target_path.exists():
            return ""

        source = self._read_file(target_path)
        if not source:
            return ""

        imports = self._extract_imports(source, language)
        if not imports:
            return ""

        context_parts: list[str] = [
            f"=== CROSS-FILE CONTEXT untuk {target_path.name} ===",
            f"File ini mengimport {len(imports)} modul/kontrak.",
            "",
        ]

        chars_used = 0
        for import_name in imports[:15]:
            imported_path = self._resolve_import(import_name, target_path, language)
            if imported_path is None:
                continue

            imported_source = self._read_file(imported_path)
            if not imported_source:
                continue

            critical_fns = self._extract_critical_functions(imported_source, language)
            caller_refs = self._find_callers(source, critical_fns)

            entry = self._format_import_entry(
                imported_path.name, import_name, critical_fns, caller_refs
            )
            if chars_used + len(entry) > max_context_chars:
                context_parts.append("... (lebih banyak import, dipotong karena batas ukuran)")
                break

            context_parts.append(entry)
            chars_used += len(entry)

        if len(context_parts) <= 3:
            return ""

        context_parts.append("=== END CROSS-FILE CONTEXT ===")
        return "\n".join(context_parts)

    def _extract_imports(self, source: str, language: str) -> list[str]:
        patterns = IMPORT_PATTERNS.get(language, [])
        imports: list[str] = []
        for pattern in patterns:
            for match in re.finditer(pattern, source, re.MULTILINE):
                imports.append(match.group(1))
        return list(dict.fromkeys(imports))

    def _resolve_import(self, import_name: str, from_file: Path, language: str) -> Path | None:
        """
        Mencoba menemukan file yang diimport di dalam repo.
        Heuristik sederhana -- tidak sempurna untuk semua module resolution
        strategy, tapi menangkap kasus yang paling umum.
        """
        # Relative path imports (./auth, ../utils/db)
        if import_name.startswith(".") or "/" in import_name:
            candidate = (from_file.parent / import_name).resolve()
            for ext in ["", ".py", ".js", ".ts", ".sol"]:
                if (candidate.with_suffix(ext) if ext else candidate).exists():
                    path = candidate.with_suffix(ext) if ext else candidate
                    if path.is_relative_to(self.repo_root):
                        return path

        # Python module-style (utils.auth -> utils/auth.py)
        if language == "python":
            module_path = import_name.replace(".", "/")
            for ext in [".py", "/__init__.py"]:
                candidate = self.repo_root / (module_path + ext)
                if candidate.exists():
                    return candidate

        # Solidity import (contracts/Token.sol)
        if language == "solidity":
            candidate = self.repo_root / import_name
            if candidate.exists():
                return candidate
            # Cari berdasarkan nama file saja sebagai fallback
            fname = Path(import_name).name
            matches = list(self.repo_root.rglob(fname))
            if len(matches) == 1:
                return matches[0]

        return None

    def _extract_critical_functions(self, source: str, language: str) -> list[str]:
        patterns = CRITICAL_FUNCTION_PATTERNS.get(language, [])
        fns: list[str] = []
        for pattern in patterns:
            for match in re.finditer(pattern, source):
                fns.append(match.group(1))
        return list(dict.fromkeys(fns))

    def _find_callers(self, source: str, functions: list[str]) -> list[str]:
        """Cari fungsi mana dari imported file yang dipanggil di file ini."""
        called = []
        for fn in functions:
            if re.search(rf"\b{re.escape(fn)}\s*\(", source):
                called.append(fn)
        return called

    def _format_import_entry(
        self, filename: str, import_name: str, critical_fns: list[str], caller_refs: list[str]
    ) -> str:
        parts = [f"  Import: {import_name} ({filename})"]
        if critical_fns:
            parts.append(f"    Fungsi kritis di file ini: {', '.join(critical_fns[:8])}")
        if caller_refs:
            parts.append(f"    Dipanggil dari file target: {', '.join(caller_refs[:5])}")
        else:
            parts.append("    (tidak ada pemanggilan langsung yang terdeteksi dari pola sederhana)")
        return "\n".join(parts)

    def _read_file(self, path: Path) -> str:
        if str(path) in self._file_cache:
            return self._file_cache[str(path)]
        try:
            content = path.read_text(errors="replace")[:6000]
            self._file_cache[str(path)] = content
            return content
        except OSError:
            return ""
