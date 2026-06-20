"""
agents/code_reader.py

Agent 1: Code Reader.
Tugasnya murni mekanis: membaca file-file relevan dan menyiapkan
potongan kode (snippet) di sekitar lokasi yang ditunjuk Evidence,
supaya agent berikutnya (Vulnerability Hunter) punya konteks kode
asli, bukan cuma deskripsi abstrak dari scanner.

Tidak ada pemanggilan LLM di sini -- ini agent "tangan", bukan "otak".
"""

from __future__ import annotations

from pathlib import Path

from core.models import Evidence

CONTEXT_LINES = 15  # berapa baris di atas/bawah lokasi finding yang disertakan


class CodeReader:
    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)

    def read_snippet_for_evidence(self, evidence: Evidence) -> tuple[str, bool]:
        """
        Mengambil snippet kode di sekitar lokasi evidence.

        Returns:
            (snippet, is_reliable) -- is_reliable False berarti path tidak
            bisa diresolusi dengan pasti dan snippet (jika ada) berasal dari
            heuristik tebakan, BUKAN file yang pasti sama dengan yang
            dilaporkan scanner. Caller (VulnerabilityHunter) WAJIB
            menurunkan confidence atau menandai finding ketika is_reliable
            False, supaya GPT tidak menganalisis kode yang salah dengan
            percaya diri penuh.
        """
        file_path, is_reliable = self._resolve_path(evidence.file_path)
        if file_path is None or not file_path.exists():
            return "", False

        try:
            lines = file_path.read_text(errors="replace").splitlines()
        except (UnicodeDecodeError, OSError):
            return "", False

        if evidence.line_start is None:
            return "\n".join(lines[:200]), is_reliable  # fallback: awal file saja

        start = max(0, evidence.line_start - 1 - CONTEXT_LINES)
        end = min(len(lines), (evidence.line_end or evidence.line_start) + CONTEXT_LINES)

        numbered = [f"{i + 1}: {lines[i]}" for i in range(start, end)]
        return "\n".join(numbered), is_reliable

    def read_full_file(self, relative_path: str, max_chars: int = 20000) -> str:
        file_path, _ = self._resolve_path(relative_path)
        if file_path is None or not file_path.exists():
            return ""
        try:
            content = file_path.read_text(errors="replace")
        except OSError:
            return ""
        return content[:max_chars]

    def _resolve_path(self, raw_path: str) -> tuple[Path | None, bool]:
        """
        Resolusi path SECARA KETAT terlebih dahulu (absolute exact match,
        atau relative terhadap repo_root). Tidak ada lagi fallback
        "cari file dengan nama sama di mana pun di repo" -- itu berbahaya
        di monorepo dengan nama file duplikat (misal banyak index.ts),
        karena bisa diam-diam mengambil file yang SALAH dan GPT akan
        menganalisis kode yang salah tanpa tahu itu salah.

        Returns (path_or_none, is_reliable).
        """
        candidate = Path(raw_path)
        if candidate.is_absolute():
            return (candidate, True) if candidate.exists() else (None, False)

        joined = self.repo_root / raw_path
        if joined.exists():
            return joined, True

        return None, False
