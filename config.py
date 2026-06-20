"""
config.py

Konfigurasi terpusat. Semua nilai bisa di-override lewat environment
variable ATAU lewat file .env di root proyek, supaya aman dipakai di
CI/server tanpa hardcode secret, dan tidak perlu export ulang manual
setiap buka terminal baru.

Setup cepat:
    cp .env.example .env
    # lalu edit .env, isi OPENAI_API_KEY=sk-...
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# --- Muat .env secara otomatis ---
# python-dotenv TIDAK menimpa environment variable yang sudah diset
# manual (misal lewat `export` atau di CI) -- .env hanya jadi fallback
# kalau variabel belum ada di environment. Ini sengaja: di server/CI,
# environment variable asli (yang biasanya diset lewat secrets manager)
# tetap diutamakan di atas isi file .env lokal.
try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except ImportError:
    # python-dotenv belum terinstal -- bukan hard requirement, supaya
    # config.py tetap bisa jalan kalau pengguna sudah set environment
    # variable secara manual tanpa file .env sama sekali. Tapi beri
    # tahu jelas, karena ini kemungkinan besar berarti pengguna lupa
    # `pip install -r requirements.txt`.
    import warnings

    warnings.warn(
        "python-dotenv tidak terinstal -- file .env (jika ada) TIDAK akan "
        "otomatis dimuat. Install dengan `pip install python-dotenv` (sudah "
        "termasuk di requirements.txt), atau set environment variable "
        "secara manual.",
        stacklevel=2,
    )

# --- OpenAI ---
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.5")
OPENAI_MODEL_FALLBACK = os.environ.get("OPENAI_MODEL_FALLBACK", "gpt-5.1")

# --- Path kerja ---
WORKDIR = Path(os.environ.get("BBAI_WORKDIR", BASE_DIR / "workdir"))
REPORTS_DIR = Path(os.environ.get("BBAI_REPORTS_DIR", BASE_DIR / "reports"))

WORKDIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# --- Binary scanner eksternal ---
# Pastikan tool ini sudah terinstal di environment Anda:
#   pip install slither-analyzer semgrep
SLITHER_BIN = os.environ.get("SLITHER_BIN", "slither")
SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")
FORGE_BIN = os.environ.get("FORGE_BIN", "forge")

# Ruleset semgrep default. "p/security-audit", "p/owasp-top-ten" adalah
# registry rules bawaan semgrep (membutuhkan koneksi internet saat pertama
# kali dipakai, lalu di-cache). Setiap elemen di-strip di sini (sumbernya),
# bukan di titik pakai -- supaya konsumen lain dari SEMGREP_RULESETS di masa
# depan tidak perlu ingat untuk strip ulang kalau user menulis ".env" dengan
# spasi setelah koma (misal "a, b" bukan "a,b" -- sangat natural ditulis manusia).
SEMGREP_RULESETS = [
    r.strip()
    for r in os.environ.get("SEMGREP_RULESETS", "p/security-audit,p/owasp-top-ten,p/secrets").split(",")
    if r.strip()
]

# --- Database findings ---
DB_PATH = os.environ.get("BBAI_DB_PATH", str(BASE_DIR / "storage" / "findings.db"))

# --- Vector DB (opsional, stub dulu) ---
QDRANT_URL = os.environ.get("QDRANT_URL", "")
QDRANT_ENABLED = bool(QDRANT_URL)

# --- Batas keamanan ---
# Exploit simulator HANYA boleh menghasilkan PoC tipe ini.
ALLOWED_POC_TYPES = {"foundry_test", "local_repro_script"}

# Timeout eksekusi tool eksternal (detik)
TOOL_TIMEOUT_SECONDS = int(os.environ.get("BBAI_TOOL_TIMEOUT", "600"))


def validate_config(check_scanners: bool = True) -> tuple[list[str], list[str]]:
    """
    Cek konfigurasi penting sebelum pipeline dijalankan.

    Returns (blocking_problems, warnings):
    - blocking_problems: HARUS diperbaiki sebelum scan dijalankan (API key).
    - warnings: tidak menghentikan eksekusi, tapi bisa menyebabkan sebagian
      scanner gagal nanti (misal Slither tidak ada tapi target ternyata
      Solidity). Scanner yang tidak applicable untuk target (lihat
      `is_applicable()` di masing-masing scanner) tidak akan pernah
      dipanggil, jadi binary yang tidak ada tidak selalu jadi masalah --
      makanya ini warning, bukan blocking problem.

    check_scanners=False untuk skip pengecekan binary -- berguna untuk
    testing/CI di mana scanner sengaja belum diinstal tapi config lain
    tetap perlu divalidasi.
    """
    problems = []
    warnings_list = []
    placeholder_values = {"sk-your-api-key-here", "sk-...", "your-api-key-here", ""}

    if not OPENAI_API_KEY or OPENAI_API_KEY in placeholder_values:
        problems.append(
            "OPENAI_API_KEY belum diset (atau masih nilai placeholder dari .env.example). "
            "Copy .env.example ke .env lalu isi nilai asli Anda, atau set environment "
            "variable OPENAI_API_KEY secara manual."
        )
    elif not OPENAI_API_KEY.startswith("sk-"):
        problems.append(
            "OPENAI_API_KEY terisi tapi tidak diawali 'sk-' -- kemungkinan format salah "
            "atau ter-copy tidak lengkap."
        )

    if check_scanners:
        import shutil

        if shutil.which(SLITHER_BIN) is None:
            warnings_list.append(
                f"Binary '{SLITHER_BIN}' (Slither) tidak ditemukan di PATH. Scan terhadap "
                f"repo Solidity akan gagal (scan repo non-Solidity tidak terpengaruh). "
                f"Install dengan: pip install slither-analyzer"
            )
        if shutil.which(SEMGREP_BIN) is None:
            warnings_list.append(
                f"Binary '{SEMGREP_BIN}' (Semgrep) tidak ditemukan di PATH. Scan terhadap "
                f"repo Python/JS/TS/Go akan gagal (scan repo Solidity-only tidak terpengaruh). "
                f"Install dengan: pip install semgrep"
            )
        if shutil.which("git") is None:
            warnings_list.append(
                "'git' tidak ditemukan di PATH -- scan terhadap URL repository (clone "
                "otomatis) tidak akan berfungsi, tapi scan path lokal tetap bisa jalan normal."
            )

    return problems, warnings_list
