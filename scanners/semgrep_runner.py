"""
scanners/semgrep_runner.py

Wrapper untuk Semgrep -- static analyzer multi-bahasa untuk
Python/JS/TS/Go/dll. Dipakai untuk mendeteksi pola bug bounty
yang spesifik (SQLi, SSRF, RCE, IDOR, path traversal, dst).

Prioritas ruleset:
1. Custom rules di rules/ (pola bug bounty spesifik, high signal-to-noise)
2. Generic registry (p/security-audit, dll) sebagai fallback tambahan
Semgrep menggabungkan semua ruleset dan mendedup secara otomatis.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

from config import BASE_DIR, SEMGREP_BIN, SEMGREP_RULESETS, TOOL_TIMEOUT_SECONDS
from core.models import Evidence
from scanners.base import BaseScanner, ScannerError

logger = logging.getLogger("bugbounty_ai.semgrep")

WEB_LANGUAGES = {"python", "javascript", "typescript", "go", "golang", "java", "ruby", "php"}

CUSTOM_RULES_DIR = BASE_DIR / "rules" / "web"


class SemgrepScanner(BaseScanner):
    name = "semgrep"

    def is_applicable(self, target_path: str, languages: list[str]) -> bool:
        return any(lang.lower() in WEB_LANGUAGES for lang in languages)

    def is_available(self) -> bool:
        return shutil.which(SEMGREP_BIN) is not None

    def run(self, target_path: str) -> list[Evidence]:
        if not self.is_available():
            raise ScannerError(
                f"'{SEMGREP_BIN}' tidak ditemukan. Install dengan: pip install semgrep"
            )

        cmd = [SEMGREP_BIN, "scan", "--json", "--quiet"]

        # Custom rules diutamakan -- ini pola bug bounty spesifik yang
        # sudah dikurasi untuk signal-to-noise tinggi.
        if CUSTOM_RULES_DIR.exists():
            cmd += ["--config", str(CUSTOM_RULES_DIR)]
        else:
            logger.warning(
                "Direktori custom rules tidak ditemukan: %s. "
                "Hanya menggunakan generic ruleset.",
                CUSTOM_RULES_DIR,
            )

        # Generic ruleset sebagai tambahan (coverage lebih luas, noise lebih tinggi).
        for ruleset in SEMGREP_RULESETS:
            cmd += ["--config", ruleset.strip()]

        cmd.append(target_path)

        result = self._run_subprocess(cmd, timeout=TOOL_TIMEOUT_SECONDS)

        try:
            data = json.loads(result.stdout) if result.stdout.strip() else None
        except json.JSONDecodeError as e:
            raise ScannerError(
                f"Semgrep tidak menghasilkan JSON valid (returncode={result.returncode}). "
                f"Stderr: {result.stderr.strip()[:2000]}"
            ) from e

        if data is None:
            raise ScannerError(
                f"Semgrep tidak menghasilkan output sama sekali (returncode={result.returncode}). "
                f"Stderr: {result.stderr.strip()[:2000]}"
            )

        scan_errors = data.get("errors", [])
        if scan_errors:
            logger.warning(
                "Semgrep melaporkan %d error parsial (file mungkin terlewat): %s",
                len(scan_errors),
                [e.get("message", "")[:200] for e in scan_errors[:3]],
            )

        evidences = self._parse_results(data)
        logger.info(
            "Semgrep: %d findings (%d dari custom rules, %d dari generic ruleset)",
            len(evidences),
            sum(1 for e in evidences if e.rule_id and "bugbounty-ai" not in (e.rule_id or "")),
            sum(1 for e in evidences if e.rule_id and "p/" in (e.rule_id or "")),
        )
        return evidences

    def _parse_results(self, data: dict) -> list[Evidence]:
        evidences: list[Evidence] = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            # Sertakan bounty_relevance dari custom rules di raw_message
            # sebagai hint ke GPT -- bukan untuk menentukan severity (itu
            # tetap tugas GPT + FP checker), tapi sebagai konteks apakah
            # temuan ini umumnya relevan untuk submission bug bounty.
            bounty_note = ""
            if metadata.get("bounty_relevance"):
                bounty_note = f" [bounty_relevance: {metadata['bounty_relevance']}]"

            evidences.append(
                Evidence(
                    source_tool="semgrep",
                    rule_id=result.get("check_id"),
                    file_path=result.get("path", "unknown"),
                    line_start=result.get("start", {}).get("line"),
                    line_end=result.get("end", {}).get("line"),
                    function_name=None,
                    raw_message=(extra.get("message", "").strip() + bounty_note),
                    raw_output=result,
                )
            )

        return evidences
