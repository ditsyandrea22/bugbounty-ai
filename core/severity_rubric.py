"""
core/severity_rubric.py

Rubrik severity yang EKSPLISIT, bukan mengandalkan "rasa" GPT terhadap
seberapa serius sebuah bug terdengar.

MASALAH YANG DIPECAHKAN:
Sebelumnya GPT diminta menilai severity tanpa rubrik konkret -- hasilnya
inconsistent antar run, dan tidak selalu align dengan bagaimana platform
bug bounty sungguhan mengklasifikasikan severity. Misal: GPT mungkin
bilang "Critical" untuk bug yang menurut kriteria Immunefi sebenarnya
"High" karena dampaknya temporer/recoverable, bukan permanent loss of funds.

PENDEKATAN:
Rubrik berikut diringkas dari kriteria publik yang dipakai Immunefi
(untuk smart contract) dan kriteria umum HackerOne/Bugcrowd (untuk web).
Ini disuntikkan ke prompt sebagai REFERENSI KONKRET yang harus diikuti
GPT saat menilai severity, bukan dibiarkan menebak sendiri.

CATATAN PENTING: rubrik ini adalah RINGKASAN dan PENYEDERHANAAN dari
kriteria publik masing-masing platform untuk tujuan panduan internal --
bukan kutipan resmi. Untuk submission sungguhan, selalu cek kriteria
TERBARU dan SPESIFIK program yang dituju, karena tiap program bug bounty
punya scope dan kriteria severity sendiri yang bisa berbeda dari rubrik
umum ini.
"""

from __future__ import annotations

SMART_CONTRACT_SEVERITY_RUBRIC = """
RUBRIK SEVERITY UNTUK SMART CONTRACT (diringkas dari kriteria umum platform
seperti Immunefi -- selalu verifikasi kriteria spesifik program yang dituju):

CRITICAL:
- Direct theft/permanent freezing dana pengguna atau protokol, TANPA butuh
  governance takeover atau kondisi eksternal yang tidak realistis
- Permanent freezing of NFT atau aset non-fungible
- Protocol insolvency (total liabilities > total assets) yang permanent
- Unauthorized minting token yang menyebabkan dilusi signifikan

HIGH:
- Theft/freezing dana yang BUTUH precondition spesifik (misal: hanya saat
  kondisi market tertentu, atau butuh capital besar dari attacker)
- Temporary freezing dana (bisa di-unfreeze, tapi butuh intervensi)
- Theft dana yang nilainya kecil relatif terhadap TVL protokol

MEDIUM:
- Griefing (attacker rugi sendiri secara ekonomi untuk merugikan korban,
  tanpa profit langsung untuk attacker)
- DoS terhadap fungsi kritikal yang butuh biaya gas signifikan untuk
  dieksploitasi attacker, atau hanya berlangsung sementara
- Theft of unclaimed yield/rewards (bukan principal)

LOW:
- Bug yang butuh precondition sangat tidak realistis untuk dieksploitasi
- Issue yang tidak punya path eksploitasi langsung ke dana/data, tapi
  menyimpang dari best practice (gas inefficiency dengan dampak, dst)

INFORMATIONAL:
- Best practice violation tanpa path eksploitasi nyata
- Code quality issue yang tidak mempengaruhi security
"""

WEB_SEVERITY_RUBRIC = """
RUBRIK SEVERITY UNTUK WEB APPLICATION (diringkas dari kriteria umum
HackerOne/Bugcrowd -- selalu verifikasi kriteria spesifik program yang dituju):

CRITICAL:
- Remote Code Execution (RCE) tanpa autentikasi
- SQL Injection yang memberi akses penuh ke database produksi
- Authentication bypass yang memberi akses admin/superuser
- Akses ke data sensitif SKALA BESAR (semua user, bukan satu akun)

HIGH:
- IDOR/Broken Access Control yang membuka akses ke data pengguna LAIN
  (bukan milik attacker sendiri), terutama data finansial/PII
- SSRF yang bisa mengakses internal network/cloud metadata
- Stored XSS yang bisa dieksekusi terhadap pengguna lain (bukan self-XSS)
- Privilege escalation dari user biasa ke admin

MEDIUM:
- Reflected XSS yang butuh interaksi user (klik link khusus)
- CSRF pada aksi yang punya dampak (bukan aksi trivial)
- Open redirect yang bisa dipakai untuk phishing
- Rate limiting yang tidak ada pada endpoint sensitif (tapi bukan auth)

LOW:
- Information disclosure yang dampaknya minor (versi software, dst)
- Self-XSS (hanya mempengaruhi akun penyerang sendiri)
- Missing security headers tanpa exploit path konkret

INFORMATIONAL:
- Best practice violation tanpa dampak security langsung
- Verbose error message tanpa data sensitif
"""


def get_severity_rubric(target_type: str) -> str:
    """target_type: 'smart_contract' atau 'web_backend' (dari ScanTarget.target_type.value)"""
    if target_type == "smart_contract":
        return SMART_CONTRACT_SEVERITY_RUBRIC
    return WEB_SEVERITY_RUBRIC
