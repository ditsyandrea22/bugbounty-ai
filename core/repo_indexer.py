"""
core/repo_indexer.py

Tahap pertama pipeline: ambil target (URL git atau path lokal),
deteksi bahasa yang dipakai, dan bangun daftar file relevan.

Catatan implementasi:
- Deteksi bahasa di sini berbasis EKSTENSI FILE (heuristik cepat & murah).
  Untuk indexing yang lebih dalam (call graph, function graph via
  tree-sitter) ini adalah titik ekstensi -- lihat TODO di bawah.
- Tidak melakukan analisis apa pun di sini, hanya orientasi.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from pathlib import Path

from core.models import ScanTarget, TargetType

EXT_LANG_MAP = {
    ".sol": "solidity",
    ".rs": "rust",
    ".move": "move",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".py": "python",
    ".go": "golang",
}

IGNORE_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    "out",
    "lib",
    "cache",
}

SOLIDITY_LANGS = {"solidity"}
WEB_LANGS = {"python", "javascript", "typescript", "golang"}


class RepoIndexer:
    def __init__(self, workdir: Path):
        self.workdir = workdir

    def cleanup(self, target: ScanTarget) -> None:
        """
        Hapus direktori clone untuk target ini SETELAH scan selesai.
        Dipisah dari _clone() supaya pipeline punya kontrol eksplisit
        kapan membersihkan (misal: tidak dihapus kalau scan gagal di
        tengah jalan dan pengguna ingin inspeksi manual).

        Hanya menghapus jika target ini berasal dari clone (punya
        repo_url) -- TIDAK PERNAH menghapus path lokal yang diberikan
        pengguna langsung (target.repo_url is None), supaya tidak pernah
        menyentuh data milik pengguna di luar workdir kerja.
        """
        if target.repo_url is None:
            return  # path lokal milik pengguna, jangan disentuh

        target_path = Path(target.path)
        if target_path.exists() and target_path.is_relative_to(self.workdir):
            shutil.rmtree(target_path, ignore_errors=True)

    def cleanup_stale_clones(self, max_age_seconds: int = 86400) -> int:
        """
        Bersihkan sisa clone lama di workdir yang lebih tua dari
        max_age_seconds (default 24 jam) -- untuk menangani kasus
        scan yang crash/terinterupsi dan tidak pernah sempat cleanup()
        normal. Mengembalikan jumlah direktori yang dihapus.
        """
        if not self.workdir.exists():
            return 0

        now = time.time()
        removed = 0
        for entry in self.workdir.iterdir():
            if not entry.is_dir():
                continue
            try:
                age = now - entry.stat().st_mtime
                if age > max_age_seconds:
                    shutil.rmtree(entry, ignore_errors=True)
                    removed += 1
            except OSError:
                continue
        return removed

    def load(self, source: str, need_full_history: bool = False) -> ScanTarget:
        """
        source bisa berupa:
        - URL git (https://github.com/... atau git@...)
        - path lokal yang sudah ada di disk

        need_full_history=True: clone TANPA --depth 1, supaya diff mode
        (--diff-base di cli.py) bisa berfungsi terhadap ref apa pun di
        history. Hanya relevan kalau source adalah URL (clone baru) --
        path lokal yang sudah ada histori-nya tidak terpengaruh parameter ini.
        Clone full history lebih lambat dan lebih besar -- hanya diaktifkan
        kalau benar-benar diminta (diff_base_ref diset).
        """
        if self._looks_like_git_url(source):
            local_path = self._clone(source, shallow=not need_full_history)
            repo_url = source
        else:
            local_path = Path(source).resolve()
            if not local_path.exists():
                raise FileNotFoundError(f"Path target tidak ditemukan: {source}")
            repo_url = None

        languages = self._detect_languages(local_path)
        target_type = self._infer_target_type(languages)

        return ScanTarget(
            path=str(local_path),
            repo_url=repo_url,
            target_type=target_type,
            languages=sorted(languages),
        )

    def list_relevant_files(self, target: ScanTarget) -> list[Path]:
        root = Path(target.path)
        files: list[Path] = []
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            if p.suffix.lower() in EXT_LANG_MAP:
                files.append(p)
        return files

    @staticmethod
    def _looks_like_git_url(source: str) -> bool:
        return source.startswith("http://") or source.startswith("https://") or source.startswith("git@")

    @staticmethod
    def _extract_repo_name(repo_url: str) -> str:
        """
        Ekstrak nama repo dari URL git, menangani baik HTTPS
        (https://github.com/org/repo.git) maupun SSH (git@github.com:org/repo.git).
        Untuk SSH, separator path setelah host adalah ':' bukan '/', jadi
        split("/")[-1] saja akan salah/ikut membawa "org:repo" tergabung.
        """
        cleaned = repo_url.rstrip("/")
        if cleaned.startswith("git@"):
            # format: git@host:org/repo.git -> ambil bagian setelah ':'
            after_colon = cleaned.split(":", 1)[-1]
            name = after_colon.split("/")[-1]
        else:
            name = cleaned.split("/")[-1]
        return name.removesuffix(".git")

    def _clone(self, repo_url: str, shallow: bool = True) -> Path:
        if shutil.which("git") is None:
            raise RuntimeError("git tidak ditemukan di PATH. Install git terlebih dahulu.")

        repo_name = self._extract_repo_name(repo_url)
        if not repo_name:
            raise ValueError(f"Tidak bisa menentukan nama repo dari URL: {repo_url}")

        # PENTING: path dest disuffix dengan timestamp + uuid pendek, BUKAN
        # hanya nama repo polos. Sebelumnya dua scan yang dijalankan
        # bersamaan terhadap repo dengan nama akhir sama (misal repo
        # "vault" dari dua org berbeda, atau scan paralel terhadap repo
        # yang sama) bisa saling rmtree() direktori yang sedang dibaca
        # proses lain. Ini hanya relevan kalau pipeline dijalankan sebagai
        # service/paralel (CLI sekuensial satu pengguna tidak terdampak),
        # tapi disiapkan dari sekarang supaya aman begitu dibungkus jadi
        # service nanti (lihat roadmap dashboard di README).
        unique_suffix = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
        dest = self.workdir / f"{repo_name}__{unique_suffix}"

        # Tidak perlu rmtree dest yang sudah ada karena nama sekarang selalu
        # unik per invocation -- tidak akan pernah collide dengan clone lain.

        cmd = ["git", "clone"]
        if shallow:
            cmd += ["--depth", "1"]
        cmd += [repo_url, str(dest)]

        # Full clone (untuk diff mode) bisa jauh lebih lambat untuk repo
        # besar -- timeout dilonggarkan dibanding shallow clone.
        timeout = 300 if shallow else 1200

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Gagal clone repo: {result.stderr.strip()}")

        return dest

    def _detect_languages(self, root: Path) -> set[str]:
        langs: set[str] = set()
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            lang = EXT_LANG_MAP.get(p.suffix.lower())
            if lang:
                langs.add(lang)
        return langs

    def _infer_target_type(self, languages: set[str]) -> TargetType:
        if languages & SOLIDITY_LANGS:
            return TargetType.SMART_CONTRACT
        if languages & WEB_LANGS:
            return TargetType.WEB_BACKEND
        return TargetType.UNKNOWN

    # TODO (ekstensi masa depan):
    #   - Integrasikan tree-sitter untuk membangun function-level call graph
    #     per bahasa, disimpan sebagai graph (networkx) untuk dipakai
    #     threat_modeler.py dalam memetakan attack surface secara presisi,
    #     bukan hanya daftar file flat seperti sekarang.
