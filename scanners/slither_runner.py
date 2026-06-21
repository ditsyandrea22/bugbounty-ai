"""
scanners/slither_runner.py

Wrapper untuk Slither (static analyzer Solidity).
Menjalankan `slither <path> --json -` dan mem-parse hasilnya jadi
list[Evidence]. Ini TIDAK menafsirkan severity/exploitability -- itu
tugas GPT di tahap selanjutnya, dengan Evidence ini sebagai bukti.

AUTO SOLC VERSION (ditambahkan setelah ditemukan di pemakaian nyata):
Sebelum Slither dijalankan, repo target di-scan untuk pragma solidity
dan versi solc yang cocok di-install/diaktifkan otomatis lewat
core/solc_manager.py. Ini mengatasi kegagalan paling umum: Slither
gagal total (returncode=1, tanpa JSON) karena versi solc aktif tidak
cocok dengan pragma kontrak.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from config import AUTO_INSTALL_DEPENDENCIES, SLITHER_BIN, TOOL_TIMEOUT_SECONDS
from core.models import Evidence
from core.solc_manager import ensure_solc_version
from scanners.base import BaseScanner, ScannerError

logger = logging.getLogger("bugbounty_ai.slither")


class SlitherScanner(BaseScanner):
    name = "slither"

    def is_applicable(self, target_path: str, languages: list[str]) -> bool:
        return "solidity" in [lang.lower() for lang in languages]

    def is_available(self) -> bool:
        return shutil.which(SLITHER_BIN) is not None

    def run(self, target_path: str) -> list[Evidence]:
        if not self.is_available():
            raise ScannerError(
                f"'{SLITHER_BIN}' tidak ditemukan. Install dengan: "
                f"pip install slither-analyzer"
            )

        # Auto-detect dan aktifkan versi solc yang cocok dengan pragma
        # repo target. Kegagalan di sini TIDAK fatal -- kalau tidak bisa
        # menentukan/install versi yang tepat, kita tetap coba jalankan
        # Slither dengan versi solc yang sudah aktif (mungkin tetap gagal,
        # tapi error message ScannerError di bawah akan tetap jelas).
        ensure_solc_version(target_path)

        if AUTO_INSTALL_DEPENDENCIES:
            self._try_auto_install_dependencies(target_path)

        cmd = [SLITHER_BIN, target_path, "--json", "-"]
        result = self._run_subprocess(cmd, timeout=TOOL_TIMEOUT_SECONDS)

        json_start = result.stdout.find("{")
        json_end = result.stdout.rfind("}")
        has_valid_json_marker = json_start != -1 and json_end != -1

        if not has_valid_json_marker:
            # Tidak ada JSON sama sekali di stdout -- ini hampir pasti
            # kegagalan eksekusi nyata (compiler error, solc version
            # mismatch, dependency belum di-build, dst), BUKAN "tidak ada
            # temuan". Tidak boleh disamarkan jadi list kosong, karena itu
            # akan terlihat seperti "kode bersih" padahal Slither tidak
            # pernah benar-benar jalan.
            #
            # PENTING (bug ditemukan di pemakaian nyata): untuk proyek
            # Foundry-based, crytic-compile sering meneruskan output
            # `forge build` APA ADANYA -- dan forge build menulis compiler
            # error ke STDOUT, bukan stderr. Versi sebelumnya hanya
            # menampilkan result.stderr di pesan error, sehingga pesan
            # error compile yang SEBENARNYA (ada di stdout) tidak pernah
            # terlihat operator -- laporan menunjukkan "Stderr: " kosong
            # padahal compiler sebenarnya menulis detail errornya di stdout.
            # Sekarang KEDUA stream ditampilkan.
            diagnostic_hints = self._diagnose_likely_cause(target_path)
            stdout_excerpt = result.stdout.strip()[:2000]
            stderr_excerpt = result.stderr.strip()[:2000]
            raise ScannerError(
                "Slither tidak menghasilkan output JSON yang valid "
                f"(returncode={result.returncode}).\n"
                f"Kemungkinan penyebab terdeteksi:\n{diagnostic_hints}\n\n"
                f"--- STDOUT dari Slither/compiler (sering berisi compile error untuk proyek Foundry) ---\n"
                f"{stdout_excerpt if stdout_excerpt else '(kosong)'}\n\n"
                f"--- STDERR dari Slither ---\n"
                f"{stderr_excerpt if stderr_excerpt else '(kosong)'}"
            )

        return self._parse_output(result.stdout, json_start, json_end)

    def _try_auto_install_dependencies(self, target_path: str) -> None:
        """
        Dipanggil HANYA kalau config.AUTO_INSTALL_DEPENDENCIES sudah
        diaktifkan eksplisit oleh operator (default mati). Mendeteksi
        Foundry/npm dependency yang belum di-install, lalu mencoba
        install sebelum Slither dijalankan -- mengatasi akar penyebab
        (bukan hanya mendiagnosis) untuk repo yang memang dipercaya
        operator.

        Kegagalan di sini TIDAK fatal -- Slither tetap dicoba setelahnya,
        dan kalau masih gagal, pesan error ScannerError akan tetap jelas.
        """
        from pathlib import Path

        root = Path(target_path)
        has_foundry_toml = (root / "foundry.toml").exists()
        has_lib_dir = (root / "lib").exists()
        lib_is_empty = has_lib_dir and not any((root / "lib").iterdir())
        has_hardhat_or_npm = any(
            (root / name).exists() for name in ["hardhat.config.js", "hardhat.config.ts", "package.json"]
        )
        has_node_modules = (root / "node_modules").exists()

        if has_foundry_toml and (not has_lib_dir or lib_is_empty):
            if shutil.which("forge") is None:
                logger.warning(
                    "AUTO_INSTALL_DEPENDENCIES aktif tapi 'forge' tidak ditemukan di PATH -- "
                    "tidak bisa auto-install dependency Foundry. Install Foundry: "
                    "https://book.getfoundry.sh/getting-started/installation"
                )
            else:
                logger.info("AUTO_INSTALL_DEPENDENCIES aktif: menjalankan `forge install` di %s", target_path)
                try:
                    result = subprocess.run(
                        ["forge", "install"],
                        cwd=target_path,
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )
                    if result.returncode != 0:
                        logger.warning(
                            "`forge install` gagal (returncode=%d): %s",
                            result.returncode,
                            result.stderr.strip()[:500],
                        )
                    else:
                        logger.info("`forge install` berhasil.")
                except subprocess.TimeoutExpired:
                    logger.warning("`forge install` timeout setelah 300s.")

        if has_hardhat_or_npm and not has_node_modules:
            if shutil.which("npm") is None:
                logger.warning(
                    "AUTO_INSTALL_DEPENDENCIES aktif tapi 'npm' tidak ditemukan di PATH -- "
                    "tidak bisa auto-install dependency npm."
                )
            else:
                logger.info("AUTO_INSTALL_DEPENDENCIES aktif: menjalankan `npm install` di %s", target_path)
                try:
                    result = subprocess.run(
                        ["npm", "install"],
                        cwd=target_path,
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )
                    if result.returncode != 0:
                        logger.warning(
                            "`npm install` gagal (returncode=%d): %s",
                            result.returncode,
                            result.stderr.strip()[:500],
                        )
                    else:
                        logger.info("`npm install` berhasil.")
                except subprocess.TimeoutExpired:
                    logger.warning("`npm install` timeout setelah 300s.")

    def _diagnose_likely_cause(self, target_path: str) -> str:
        """
        Heuristik diagnostik -- cek tanda-tanda umum kenapa Slither gagal,
        SELAIN solc version mismatch (yang sudah ditangani ensure_solc_version).
        Repo kompleks dengan banyak dependency (Foundry/Hardhat remapping,
        npm package) sering gagal compile kalau dependency belum di-install/
        build, terlepas dari versi solc sudah benar.
        """
        from pathlib import Path

        root = Path(target_path)
        hints = []

        has_foundry_toml = (root / "foundry.toml").exists()
        has_hardhat_config = any(
            (root / name).exists() for name in ["hardhat.config.js", "hardhat.config.ts"]
        )
        has_package_json = (root / "package.json").exists()
        has_node_modules = (root / "node_modules").exists()
        has_lib_dir = (root / "lib").exists()  # forge dependency convention
        has_remappings_file = (root / "remappings.txt").exists()

        if has_foundry_toml and not has_lib_dir:
            hints.append(
                "- Terdeteksi foundry.toml tapi folder lib/ tidak ada -- dependency Foundry "
                "kemungkinan belum di-install. PERBAIKAN: jalankan `forge install` di dalam "
                f"repo ({target_path}) sebelum scan ulang."
            )
        elif has_foundry_toml and has_lib_dir:
            lib_contents = list((root / "lib").iterdir()) if (root / "lib").exists() else []
            if not lib_contents:
                hints.append(
                    "- Folder lib/ ada tapi KOSONG -- dependency Foundry kemungkinan gagal "
                    f"di-clone (submodule belum di-init). PERBAIKAN: jalankan `forge install` "
                    f"atau `git submodule update --init --recursive` di dalam repo ({target_path})."
                )

        if (has_hardhat_config or has_package_json) and not has_node_modules:
            hints.append(
                "- Terdeteksi package.json/hardhat.config tapi node_modules/ tidak ada -- "
                f"dependency npm kemungkinan belum di-install. PERBAIKAN: jalankan `npm install` "
                f"di dalam repo ({target_path}) sebelum scan ulang."
            )

        # Validasi NYATA path remapping terhadap disk -- bukan cuma cek
        # file remappings.txt ada, tapi benar-benar baca isinya dan cek
        # apakah target path-nya benar-benar ada. Ini jauh lebih actionable
        # daripada saran generik "pastikan path remapping valid".
        remapping_issues = self._validate_remappings(root, has_foundry_toml, has_remappings_file)
        if remapping_issues:
            hints.extend(remapping_issues)
        elif has_remappings_file or has_foundry_toml:
            hints.append(
                "- Remapping terdeteksi dan semua path target-nya ADA di disk (bukan ini "
                "penyebabnya kalau ada hint lain di atas yang lebih cocok)."
            )

        if not hints:
            hints.append(
                "- Tidak terdeteksi tanda dependency yang jelas hilang. Kemungkinan murni "
                "versi solc tidak cocok (auto-detect sudah dicoba) atau error sintaks di kontrak. "
                "Lihat STDOUT di bawah -- untuk proyek Foundry, compiler error sering muncul di sana."
            )

        return "\n".join(hints)

    def _validate_remappings(
        self, root, has_foundry_toml: bool, has_remappings_file: bool
    ) -> list[str]:
        """
        Membaca remapping nyata (dari remappings.txt ATAU foundry.toml
        [profile.default] remappings=[...]) dan mengecek apakah target
        path tiap remapping benar-benar ada di disk. Mengembalikan list
        pesan untuk setiap remapping yang targetnya TIDAK DITEMUKAN --
        ini kemungkinan besar akar penyebab compile error untuk proyek
        dengan banyak dependency seperti yang ditemukan di pemakaian nyata.
        """
        issues = []
        remap_lines: list[str] = []

        remappings_file = root / "remappings.txt"
        if has_remappings_file:
            try:
                remap_lines.extend(
                    line.strip() for line in remappings_file.read_text(errors="replace").splitlines() if line.strip()
                )
            except OSError:
                pass

        if has_foundry_toml:
            try:
                foundry_toml_content = (root / "foundry.toml").read_text(errors="replace")
                # Parsing minimal TOML array tanpa dependency eksternal --
                # cukup untuk pola umum `remappings = ["a=b", "c=d"]`.
                import re

                match = re.search(r"remappings\s*=\s*\[(.*?)\]", foundry_toml_content, re.DOTALL)
                if match:
                    entries = re.findall(r'["\']([^"\']+)["\']', match.group(1))
                    remap_lines.extend(entries)
            except OSError:
                pass

        for line in remap_lines:
            if "=" not in line:
                continue
            alias, _, target = line.partition("=")
            target = target.strip()
            if not target:
                continue
            target_path_on_disk = root / target
            if not target_path_on_disk.exists():
                issues.append(
                    f"- Remapping '{alias.strip()}={target}' menunjuk ke path yang TIDAK ADA "
                    f"di disk ({target_path_on_disk}). PERBAIKAN: jalankan `forge install` untuk "
                    f"memastikan dependency ter-clone, atau periksa apakah remapping ini benar "
                    f"relatif terhadap root repo."
                )

        return issues

    def _parse_output(self, raw_stdout: str, json_start: int, json_end: int) -> list[Evidence]:
        try:
            data = json.loads(raw_stdout[json_start : json_end + 1])
        except json.JSONDecodeError as e:
            raise ScannerError(f"Output Slither terlihat seperti JSON tapi gagal di-parse: {e}") from e

        # Slither sendiri punya field "success" di JSON-nya untuk
        # menandakan apakah analisis benar-benar berhasil.
        if data.get("success") is False:
            error_msg = data.get("error", "tidak ada detail error dari Slither")
            raise ScannerError(f"Slither melaporkan analisis gagal: {error_msg}")

        evidences: list[Evidence] = []
        results = data.get("results", {})
        detectors = results.get("detectors", [])

        for det in detectors:
            check = det.get("check", "unknown")
            description = det.get("description", "").strip()
            elements = det.get("elements", [])

            file_path = "unknown"
            line_start = None
            line_end = None
            function_name = None

            for el in elements:
                src_mapping = el.get("source_mapping", {})
                if src_mapping:
                    file_path = src_mapping.get("filename_relative") or src_mapping.get(
                        "filename_absolute", file_path
                    )
                    lines = src_mapping.get("lines", [])
                    if lines:
                        line_start = min(lines)
                        line_end = max(lines)
                if el.get("type") == "function":
                    function_name = el.get("name")
                if function_name:
                    break

            evidences.append(
                Evidence(
                    source_tool="slither",
                    rule_id=check,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    function_name=function_name,
                    raw_message=description,
                    raw_output=det,
                )
            )

        return evidences
