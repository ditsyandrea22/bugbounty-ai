"""
scanners/base.py

Interface abstrak untuk semua static/dynamic analyzer.
Setiap scanner WAJIB mengembalikan list[Evidence] -- bukan Finding.
Keputusan "apakah ini benar-benar bug" ada di tangan GPT + FP checker,
bukan di scanner. Scanner hanya melaporkan apa yang ia lihat.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.models import Evidence


class ScannerError(RuntimeError):
    """Dilempar saat tool eksternal gagal dieksekusi atau binary tidak ditemukan."""


@dataclass
class SubprocessResult:
    stdout: str
    stderr: str
    returncode: int


class BaseScanner(ABC):
    name: str = "base"

    @abstractmethod
    def is_applicable(self, target_path: str, languages: list[str]) -> bool:
        """Apakah scanner ini relevan untuk target ini?"""
        raise NotImplementedError

    @abstractmethod
    def run(self, target_path: str) -> list[Evidence]:
        """Jalankan scanner, kembalikan evidence mentah."""
        raise NotImplementedError

    def _run_subprocess(self, cmd: list[str], cwd: str | None = None, timeout: int = 600) -> SubprocessResult:
        """
        PENTING: ini mengembalikan stdout dan stderr SECARA TERPISAH
        (bukan digabung dengan fallback `or` seperti versi sebelumnya).

        Alasan: banyak security scanner (slither, semgrep) memang
        mengembalikan exit code != 0 KETIKA MENEMUKAN FINDING -- itu bukan
        error. Tapi exit code != 0 DENGAN stdout kosong/tidak valid JSON
        biasanya berarti tool benar-benar gagal jalan (misal solc version
        mismatch). Subclass yang harus menafsirkan kombinasi
        (returncode, stdout, stderr) ini secara eksplisit -- jangan
        ditebak secara implisit di base class.
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as e:
            raise ScannerError(
                f"Binary tidak ditemukan untuk menjalankan: {' '.join(cmd)}. "
                f"Pastikan tool '{cmd[0]}' sudah terinstal dan ada di PATH."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"Timeout menjalankan: {' '.join(cmd)}") from e

        return SubprocessResult(stdout=result.stdout, stderr=result.stderr, returncode=result.returncode)
