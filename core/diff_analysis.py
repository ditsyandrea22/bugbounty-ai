"""
core/diff_analysis.py

Diff-aware scanning: fokus ke perubahan dari versi/commit sebelumnya,
bukan selalu scan seluruh repo dari nol.

MASALAH YANG DIPECAHKAN:
Bug bounty yang paling menguntungkan sering muncul di UPGRADE -- patch
yang memperkenalkan vulnerability baru, atau yang menghilangkan mitigasi
yang sebelumnya ada. Scan penuh ke seluruh codebase setiap kali punya
signal-to-noise ratio rendah dibanding fokus ke yang BARU DIUBAH.

PENDEKATAN:
Gunakan `git diff` antara dua ref (branch/tag/commit) untuk dapat daftar
file yang berubah, lalu:
1. Filter evidence dari scanner agar hanya yang menyentuh file yang berubah
2. Suntikkan diff content sebagai context tambahan ke GPT, supaya GPT
   tahu APA yang berubah -- ini penting karena bug introduksi sering
   hanya terlihat jelas saat dibandingkan dengan versi lama (misal:
   mitigasi yang dihapus).
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from core.models import Evidence

logger = logging.getLogger("bugbounty_ai.diff_analysis")


class DiffAnalyzer:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def is_git_repo(self) -> bool:
        return (self.repo_path / ".git").exists()

    def is_shallow_clone(self) -> bool:
        """
        Cek apakah repo ini shallow clone (history terbatas, hasil dari
        `git clone --depth 1` -- lihat repo_indexer.py::_clone). Diff
        terhadap ref yang berada di luar history yang ter-fetch akan
        gagal dengan error git yang membingungkan ("bad revision" atau
        serupa) kalau ini tidak dideteksi lebih dulu.
        """
        shallow_file = self.repo_path / ".git" / "shallow"
        return shallow_file.exists()

    def get_changed_files(self, base_ref: str, target_ref: str = "HEAD") -> list[str]:
        """
        Mengembalikan daftar path file (relatif terhadap repo root) yang
        berubah antara base_ref dan target_ref.
        """
        if not self.is_git_repo():
            raise ValueError(f"{self.repo_path} bukan git repository (tidak ada .git).")

        if self.is_shallow_clone():
            raise RuntimeError(
                f"Repository ini adalah SHALLOW CLONE (history terbatas, biasanya hasil "
                f"`git clone --depth 1` yang dipakai sistem ini saat scan dari URL). "
                f"Diff terhadap ref '{base_ref}' kemungkinan besar akan gagal karena commit "
                f"itu tidak ter-fetch. Untuk memakai --diff-base, clone manual dengan history "
                f"lengkap dahulu (`git clone <url>` tanpa --depth), lalu jalankan scan "
                f"terhadap path lokal hasil clone tersebut, bukan URL langsung."
            )

        result = subprocess.run(
            ["git", "diff", "--name-only", base_ref, target_ref],
            cwd=str(self.repo_path),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git diff gagal (base={base_ref}, target={target_ref}): {result.stderr.strip()}"
            )

        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def get_diff_content(self, file_path: str, base_ref: str, target_ref: str = "HEAD") -> str:
        """Mengembalikan unified diff untuk satu file spesifik."""
        result = subprocess.run(
            ["git", "diff", base_ref, target_ref, "--", file_path],
            cwd=str(self.repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return ""
        return result.stdout

    def filter_evidence_to_changed_files(
        self, evidences: list[Evidence], changed_files: list[str]
    ) -> tuple[list[Evidence], int]:
        """
        Filter evidence agar hanya yang menyentuh file di changed_files.
        Returns (filtered_evidences, jumlah_yang_difilter_keluar).

        Matching dilakukan dengan normalisasi path (suffix match) karena
        evidence.file_path bisa berupa path absolut atau relatif tergantung
        scanner, sementara changed_files dari git diff selalu relatif
        terhadap repo root.
        """
        changed_set = {self._normalize(f) for f in changed_files}
        filtered = []
        excluded_count = 0

        for ev in evidences:
            normalized_ev_path = self._normalize(ev.file_path)
            if any(
                normalized_ev_path.endswith(cf) or cf.endswith(normalized_ev_path)
                for cf in changed_set
            ):
                filtered.append(ev)
            else:
                excluded_count += 1

        return filtered, excluded_count

    @staticmethod
    def _normalize(path: str) -> str:
        return path.replace("\\", "/").lstrip("/")
