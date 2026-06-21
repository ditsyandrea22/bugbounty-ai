"""
core/solc_manager.py

Auto-detect dan auto-install versi solc yang cocok dengan pragma kontrak
target, SEBELUM Slither dijalankan.

MASALAH YANG DIPECAHKAN:
Slither gagal total (returncode=1, tanpa output JSON) kalau versi solc
yang aktif tidak cocok dengan pragma di kontrak target -- ini ditemukan
di pemakaian nyata (repo dengan pragma ^0.8.x sementara solc aktif di
environment beda versi). Sebelumnya operator harus manual jalankan
`solc-select install X.Y.Z && solc-select use X.Y.Z` setiap ganti target
repo -- mudah terlewat, dan kegagalannya tidak jelas sebabnya dari luar.

PENDEKATAN:
1. Scan semua file .sol di repo, ekstrak pragma version statement.
2. Tentukan versi solc yang paling cocok (versi tertinggi yang memenuhi
   SEMUA constraint pragma yang ditemukan -- kontrak besar sering punya
   banyak file dengan pragma sedikit berbeda, misal beberapa "^0.8.19"
   dan beberapa "^0.8.20").
3. Cek apakah versi itu sudah terinstal via solc-select; install kalau
   belum (sekali per versi, hasilnya persistent di cache solc-select).
4. Set sebagai versi aktif sebelum Slither dipanggil.

INI BUKAN SOLUSI SEMPURNA:
- Kalau resolusi constraint multi-file gagal (pragma yang benar-benar
  tidak kompatibel satu sama lain dalam satu repo -- jarang tapi
  mungkin), operator tetap perlu intervensi manual.
- Instalasi versi solc baru butuh koneksi internet (download binary) --
  kalau gagal, error akan jelas (bukan disamarkan), dan Slither tetap
  dicoba dengan versi yang sudah aktif sebagai fallback.
- Tidak menangani kasus kontrak yang sengaja butuh banyak versi solc
  BERBEDA untuk file berbeda dalam satu deployment (foundry/hardhat
  remapping kompleks) -- itu di luar scope perbaikan ini.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger("bugbounty_ai.solc_manager")

SOLC_SELECT_BIN = "solc-select"

# Pola pragma solidity, contoh yang harus tertangkap:
#   pragma solidity ^0.8.19;
#   pragma solidity >=0.8.0 <0.9.0;
#   pragma solidity 0.8.20;
#   pragma solidity ~0.8.17;
_PRAGMA_PATTERN = re.compile(r"pragma\s+solidity\s+([^;]+);")

# Versi solc yang dikenal stabil dan banyak dipakai, dipakai sebagai
# kandidat utama saat memilih versi yang memenuhi constraint -- diurutkan
# dari yang lebih baru, supaya begitu ketemu yang cocok, itu kemungkinan
# besar versi yang dimaksud author kontrak (bukan versi sangat lawas).
_KNOWN_SOLC_VERSIONS = [
    "0.8.28", "0.8.27", "0.8.26", "0.8.25", "0.8.24", "0.8.23", "0.8.22",
    "0.8.21", "0.8.20", "0.8.19", "0.8.18", "0.8.17", "0.8.16", "0.8.15",
    "0.8.14", "0.8.13", "0.8.12", "0.8.11", "0.8.10", "0.8.9", "0.8.8",
    "0.8.7", "0.8.6", "0.8.5", "0.8.4", "0.8.3", "0.8.2", "0.8.1", "0.8.0",
    "0.7.6", "0.7.5", "0.7.4", "0.7.3", "0.7.2", "0.7.1", "0.7.0",
    "0.6.12", "0.6.11", "0.6.10", "0.6.8", "0.6.6", "0.6.0",
    "0.5.17", "0.5.16", "0.5.0",
    "0.4.26", "0.4.25", "0.4.24", "0.4.18", "0.4.11",
]


class SolcManagerError(RuntimeError):
    pass


def is_solc_select_available() -> bool:
    return shutil.which(SOLC_SELECT_BIN) is not None


def extract_pragma_constraints(repo_path: str) -> list[str]:
    """Scan semua file .sol di repo, kembalikan daftar pragma constraint mentah."""
    root = Path(repo_path)
    constraints: list[str] = []

    for sol_file in root.rglob("*.sol"):
        if any(part in {"node_modules", "lib", "out", "cache", "artifacts"} for part in sol_file.parts):
            continue
        try:
            content = sol_file.read_text(errors="replace")
        except OSError:
            continue
        for match in _PRAGMA_PATTERN.finditer(content):
            constraints.append(match.group(1).strip())

    return constraints


def _version_satisfies(version: str, constraint: str) -> bool:
    """
    Cek apakah `version` (contoh "0.8.20") memenuhi `constraint` (contoh
    "^0.8.19", ">=0.8.0 <0.9.0", "0.8.20", "~0.8.17").

    Implementasi minimal -- menangani operator yang umum dipakai (^, ~,
    >=, <=, >, <, =) tanpa dependency eksternal. TIDAK selengkap semver
    library penuh, tapi cukup untuk kasus pragma Solidity yang umum.
    """

    def parse(v: str) -> tuple[int, int, int]:
        parts = v.strip().lstrip("=").split(".")
        padded = (parts + ["0", "0", "0"])[:3]
        return (int(padded[0]), int(padded[1]), int(padded[2]))

    v = parse(version)

    clauses = constraint.split()
    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue

        if clause.startswith("^"):
            base = parse(clause[1:])
            if base[0] == 0:
                if not (v[0] == 0 and v[1] == base[1] and v[2] >= base[2]):
                    return False
            else:
                if not (v[0] == base[0] and (v[1], v[2]) >= (base[1], base[2])):
                    return False
        elif clause.startswith("~"):
            base = parse(clause[1:])
            if not (v[0] == base[0] and v[1] == base[1] and v[2] >= base[2]):
                return False
        elif clause.startswith(">="):
            if v < parse(clause[2:]):
                return False
        elif clause.startswith("<="):
            if v > parse(clause[2:]):
                return False
        elif clause.startswith(">"):
            if v <= parse(clause[1:]):
                return False
        elif clause.startswith("<"):
            if v >= parse(clause[1:]):
                return False
        elif clause.startswith("="):
            if v != parse(clause[1:]):
                return False
        else:
            if v != parse(clause):
                return False

    return True


def resolve_best_version(constraints: list[str]) -> str | None:
    """
    Cari satu versi solc yang memenuhi SEMUA constraint yang ditemukan,
    dari kandidat versi yang dikenal (terbaru duluan). Mengembalikan None
    kalau tidak ada satu versi pun yang memenuhi semua constraint
    (kemungkinan pragma antar file benar-benar tidak kompatibel).
    """
    if not constraints:
        return None

    unique_constraints = list(dict.fromkeys(constraints))

    for candidate in _KNOWN_SOLC_VERSIONS:
        if all(_version_satisfies(candidate, c) for c in unique_constraints):
            return candidate

    return None


def ensure_solc_version(repo_path: str, timeout: int = 120) -> str | None:
    """
    Fungsi utama: deteksi pragma di repo, tentukan versi terbaik, install
    kalau belum ada, set sebagai versi aktif. Mengembalikan versi yang
    diaktifkan, atau None kalau tidak bisa menentukan/mengaktifkan versi
    apa pun (caller harus lanjut dengan versi solc yang sudah aktif
    sebagai fallback, bukan menganggap ini fatal).
    """
    if not is_solc_select_available():
        logger.warning(
            "'%s' tidak ditemukan -- tidak bisa auto-switch versi solc. "
            "Kalau Slither gagal karena version mismatch, install manual: "
            "pip install solc-select && solc-select install <versi> && "
            "solc-select use <versi>",
            SOLC_SELECT_BIN,
        )
        return None

    constraints = extract_pragma_constraints(repo_path)
    if not constraints:
        logger.info("Tidak ada pragma solidity ditemukan di repo -- skip auto solc-select.")
        return None

    best_version = resolve_best_version(constraints)
    if best_version is None:
        sample = list(dict.fromkeys(constraints))[:5]
        logger.warning(
            "Tidak ada versi solc dikenal yang memenuhi SEMUA pragma constraint "
            "yang ditemukan (%s). Pragma di file-file berbeda mungkin benar-benar "
            "tidak kompatibel -- Slither akan dicoba dengan versi solc yang sudah "
            "aktif, kemungkinan tetap gagal untuk sebagian file.",
            sample,
        )
        return None

    installed = _list_installed_versions()
    if best_version not in installed:
        logger.info("Versi solc %s belum terinstal -- menginstal sekarang...", best_version)
        try:
            subprocess.run(
                [SOLC_SELECT_BIN, "install", best_version],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(
                "Gagal menginstal solc %s (%s) -- kemungkinan tidak ada koneksi "
                "internet atau versi tidak valid. Slither akan dicoba dengan versi "
                "solc yang sudah aktif.",
                best_version,
                e.stderr.strip()[:300] if e.stderr else str(e),
            )
            return None
        except subprocess.TimeoutExpired:
            logger.warning("Timeout menginstal solc %s setelah %ds.", best_version, timeout)
            return None

    try:
        subprocess.run(
            [SOLC_SELECT_BIN, "use", best_version],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        logger.info("Versi solc aktif diset ke %s (terdeteksi dari pragma repo).", best_version)
        return best_version
    except subprocess.CalledProcessError as e:
        logger.warning(
            "Gagal mengaktifkan solc %s: %s", best_version, e.stderr.strip()[:300] if e.stderr else str(e)
        )
        return None


def _list_installed_versions() -> set[str]:
    try:
        result = subprocess.run(
            [SOLC_SELECT_BIN, "versions"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        versions = set()
        for line in result.stdout.splitlines():
            v = line.strip().split()[0] if line.strip() else ""
            if v:
                versions.add(v)
        return versions
    except (subprocess.TimeoutExpired, OSError):
        return set()
