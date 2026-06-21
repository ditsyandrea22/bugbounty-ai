"""
scanners/zap_runner.py

Wrapper untuk OWASP ZAP -- DYNAMIC analyzer yang menguji aplikasi web yang
BENAR-BENAR BERJALAN (live), bukan membaca source code statis.

PERBEDAAN FUNDAMENTAL dari Slither/Semgrep:
- Slither/Semgrep: analisis source code, tidak butuh aplikasi running.
- ZAP: mengirim HTTP request NYATA ke target URL, menganalisis response.
  Butuh target yang benar-benar bisa diakses (localhost dev server, staging
  environment, atau -- HANYA dengan izin eksplisit -- target bug bounty
  yang sudah dikonfirmasi dalam scope program).

CARA KERJA:
ZAP dijalankan sebagai daemon terpisah (proses background) yang expose REST
API di localhost. Wrapper ini TIDAK menjalankan/menginstall ZAP -- itu
prasyarat yang harus disiapkan operator (lihat README). Wrapper ini hanya
menjadi klien dari ZAP API yang sudah berjalan, dengan urutan:
1. Spider/crawl target untuk menemukan endpoint
2. Jalankan active scan (mengirim payload uji ke tiap endpoint ditemukan)
3. Ambil hasil alert dari ZAP, ubah jadi Evidence

PERINGATAN KERAS -- INI MENGIRIM TRAFFIC NYATA KE TARGET:
Active scan ZAP mengirim ribuan request dengan payload uji (SQLi, XSS, dst)
ke SETIAP endpoint yang ditemukan. Ini:
- TIDAK PERNAH dijalankan terhadap target tanpa izin eksplisit pemilik
  sistem, atau program bug bounty resmi yang mengizinkan automated scanning.
- Bisa membuat noise besar di log target, memicu rate-limiting/WAF block,
  atau dalam kasus tertentu mempengaruhi data (kalau ada endpoint yang
  melakukan write operation tanpa idempotency).
- Wrapper ini akan menolak menjalankan scan terhadap domain yang terlihat
  seperti domain pihak ketiga acak -- lihat _validate_target_authorized().
  Ini bukan pengaman sempurna (operator yang punya izin sah tetap harus
  konfirmasi manual), tapi mencegah kesalahan ketik/kecerobohan paling umum.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from dataclasses import dataclass

from core.models import Evidence
from scanners.base import ScannerError

logger = logging.getLogger("bugbounty_ai.zap")

# Domain yang TIDAK PERNAH diizinkan sebagai target active scan, bahkan
# kalau diketik manual oleh operator -- safety net paling dasar untuk
# mencegah scan tidak sengaja terhadap infrastruktur pihak ketiga besar
# yang jelas-jelas bukan target audit yang dimaksud.
_NEVER_SCAN_DOMAINS = {
    "google.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "github.com", "cloudflare.com", "openai.com",
    "anthropic.com",
}

LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


@dataclass
class ZapConfig:
    zap_api_url: str = "http://localhost:8080"
    api_key: str = ""
    spider_timeout_seconds: int = 300
    active_scan_timeout_seconds: int = 1800  # active scan bisa lama untuk app besar
    poll_interval_seconds: int = 5


class ZapAuthorizationError(ScannerError):
    """Dilempar saat target tidak lolos pengecekan otorisasi dasar."""


class ZapScanner:
    """
    Bukan subclass BaseScanner -- ZAP punya siklus hidup berbeda (butuh
    target URL bukan path lokal, butuh konfirmasi otorisasi eksplisit,
    durasi jauh lebih lama). Dipanggil secara terpisah dari pipeline utama,
    lihat core/pipeline.py::AuditPipeline.run_dynamic_scan().
    """

    name = "owasp_zap"

    def __init__(self, config: ZapConfig | None = None):
        self.config = config or ZapConfig()
        self._session = None  # lazy import requests, lihat _get_session()

    def _get_session(self):
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def is_available(self) -> bool:
        """Cek apakah ZAP daemon sedang berjalan dan API bisa dihubungi."""
        try:
            session = self._get_session()
            resp = session.get(
                f"{self.config.zap_api_url}/JSON/core/view/version/",
                params={"apikey": self.config.api_key},
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    def run(self, target_url: str, confirm_authorized: bool = False) -> list[Evidence]:
        """
        Menjalankan spider + active scan terhadap target_url, mengembalikan
        Evidence dari alert yang ditemukan ZAP.

        confirm_authorized=True WAJIB diset eksplisit oleh caller (bukan
        default True) -- ini bukan hanya formalitas, ini memaksa setiap
        titik pemanggilan untuk secara sadar menyatakan bahwa scan ini
        sudah diotorisasi, bukan dijalankan asal oleh kelalaian.
        """
        if not confirm_authorized:
            raise ZapAuthorizationError(
                "Active scan ZAP TIDAK dijalankan tanpa konfirmasi eksplisit. "
                "Active scan mengirim traffic NYATA ke target dan hanya boleh "
                "dijalankan terhadap (a) environment lokal/development milik Anda, "
                "atau (b) target bug bounty yang SUDAH dikonfirmasi dalam scope "
                "program resmi. Set confirm_authorized=True hanya setelah memverifikasi "
                "ini, lihat cli.py untuk flag --confirm-authorized di command line."
            )

        self._validate_target_authorized(target_url)

        if not self.is_available():
            raise ScannerError(
                f"ZAP API tidak bisa dihubungi di {self.config.zap_api_url}. "
                f"Pastikan ZAP daemon berjalan, contoh: "
                f"zap.sh -daemon -port 8080 -config api.key=<your-key>"
            )

        logger.info("Memulai spider terhadap %s", target_url)
        self._run_spider(target_url)

        logger.info("Spider selesai. Memulai active scan terhadap %s", target_url)
        logger.warning(
            "ACTIVE SCAN MENGIRIM TRAFFIC NYATA ke %s. Ini bisa memicu rate-limiting "
            "atau WAF di sisi target -- ini diharapkan untuk scan yang sah.",
            target_url,
        )
        self._run_active_scan(target_url)

        logger.info("Active scan selesai. Mengambil alerts.")
        return self._fetch_alerts_as_evidence(target_url)

    def _validate_target_authorized(self, target_url: str) -> None:
        parsed = urllib.parse.urlparse(target_url)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            raise ZapAuthorizationError(f"URL target tidak valid: {target_url}")

        if hostname in LOCAL_HOSTS:
            return  # localhost selalu diizinkan -- ini environment milik operator

        for blocked in _NEVER_SCAN_DOMAINS:
            if hostname == blocked or hostname.endswith(f".{blocked}"):
                raise ZapAuthorizationError(
                    f"Target '{hostname}' ada di daftar domain yang TIDAK PERNAH "
                    f"diizinkan untuk active scan (kemungkinan besar ini infrastruktur "
                    f"pihak ketiga, bukan target audit yang dimaksud). Kalau Anda yakin "
                    f"ini benar-benar target yang sah dalam scope program bug bounty "
                    f"resmi, ini kemungkinan kesalahan ketik domain -- periksa kembali."
                )

    def _run_spider(self, target_url: str) -> None:
        session = self._get_session()
        resp = session.get(
            f"{self.config.zap_api_url}/JSON/spider/action/scan/",
            params={"apikey": self.config.api_key, "url": target_url},
            timeout=30,
        )
        resp.raise_for_status()
        scan_id = resp.json().get("scan")

        deadline = time.time() + self.config.spider_timeout_seconds
        while time.time() < deadline:
            status_resp = session.get(
                f"{self.config.zap_api_url}/JSON/spider/view/status/",
                params={"apikey": self.config.api_key, "scanId": scan_id},
                timeout=10,
            )
            progress = int(status_resp.json().get("status", "0"))
            if progress >= 100:
                return
            time.sleep(self.config.poll_interval_seconds)

        logger.warning(
            "Spider tidak selesai dalam %ds (timeout) -- lanjut ke active scan "
            "dengan endpoint yang sudah ditemukan sejauh ini.",
            self.config.spider_timeout_seconds,
        )

    def _run_active_scan(self, target_url: str) -> None:
        session = self._get_session()
        resp = session.get(
            f"{self.config.zap_api_url}/JSON/ascan/action/scan/",
            params={"apikey": self.config.api_key, "url": target_url},
            timeout=30,
        )
        resp.raise_for_status()
        scan_id = resp.json().get("scan")

        deadline = time.time() + self.config.active_scan_timeout_seconds
        while time.time() < deadline:
            status_resp = session.get(
                f"{self.config.zap_api_url}/JSON/ascan/view/status/",
                params={"apikey": self.config.api_key, "scanId": scan_id},
                timeout=10,
            )
            progress = int(status_resp.json().get("status", "0"))
            if progress >= 100:
                return
            time.sleep(self.config.poll_interval_seconds)

        logger.warning(
            "Active scan tidak selesai dalam %ds (timeout) -- mengambil alert "
            "yang sudah ditemukan sejauh ini, kemungkinan tidak lengkap.",
            self.config.active_scan_timeout_seconds,
        )

    def _fetch_alerts_as_evidence(self, target_url: str) -> list[Evidence]:
        session = self._get_session()
        resp = session.get(
            f"{self.config.zap_api_url}/JSON/core/view/alerts/",
            params={"apikey": self.config.api_key, "baseurl": target_url},
            timeout=30,
        )
        resp.raise_for_status()
        alerts = resp.json().get("alerts", [])

        evidences = []
        for alert in alerts:
            evidences.append(
                Evidence(
                    source_tool="owasp_zap",
                    rule_id=alert.get("pluginId", alert.get("alertRef", "unknown")),
                    file_path=alert.get("url", target_url),  # "file_path" dipakai sebagai URL endpoint
                    line_start=None,
                    line_end=None,
                    function_name=alert.get("method"),  # HTTP method (GET/POST/dst)
                    raw_message=(
                        f"[{alert.get('risk', '?')}] {alert.get('name', '')}: "
                        f"{alert.get('description', '')[:500]}"
                    ),
                    raw_output=alert,
                )
            )

        logger.info("ZAP menghasilkan %d alert.", len(evidences))
        return evidences
