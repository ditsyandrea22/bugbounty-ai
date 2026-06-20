"""
scanners/slither_runner.py

Wrapper untuk Slither (static analyzer Solidity).
Menjalankan `slither <path> --json -` dan mem-parse hasilnya jadi
list[Evidence]. Ini TIDAK menafsirkan severity/exploitability -- itu
tugas GPT di tahap selanjutnya, dengan Evidence ini sebagai bukti.
"""

from __future__ import annotations

import json
import shutil

from config import SLITHER_BIN, TOOL_TIMEOUT_SECONDS
from core.models import Evidence
from scanners.base import BaseScanner, ScannerError


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

        cmd = [SLITHER_BIN, target_path, "--json", "-"]
        result = self._run_subprocess(cmd, timeout=TOOL_TIMEOUT_SECONDS)

        json_start = result.stdout.find("{")
        json_end = result.stdout.rfind("}")
        has_valid_json_marker = json_start != -1 and json_end != -1

        if not has_valid_json_marker:
            # Tidak ada JSON sama sekali di stdout -- ini hampir pasti
            # kegagalan eksekusi nyata (compiler error, solc version
            # mismatch, dst), BUKAN "tidak ada temuan". Tidak boleh
            # disamarkan jadi list kosong, karena itu akan terlihat seperti
            # "kode bersih" padahal Slither tidak pernah benar-benar jalan.
            raise ScannerError(
                "Slither tidak menghasilkan output JSON yang valid "
                f"(returncode={result.returncode}). Kemungkinan penyebab: "
                "versi solc tidak cocok dengan pragma kontrak, atau error "
                "kompilasi. Stderr dari Slither:\n"
                f"{result.stderr.strip()[:2000]}"
            )

        return self._parse_output(result.stdout, json_start, json_end)

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
