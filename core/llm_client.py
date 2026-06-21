"""
core/llm_client.py

Wrapper tunggal untuk semua pemanggilan OpenAI di proyek ini.
Tujuannya: satu titik kontrol untuk model, retry, dan parsing JSON,
supaya agent lain tidak perlu tahu detail API.

PENTING: GPT di sini TIDAK PERNAH dipanggil tanpa evidence dari scanner
nyata sebagai konteks. Lihat agents/vulnerability_hunter.py untuk
bagaimana evidence di-supply ke prompt.

STRATEGI RETRY (diperbaiki dari versi awal):
- Exponential backoff antar retry (1s, 2s, 4s, ...) -- retry tanpa delay
  untuk error rate limit (HTTP 429) nyaris pasti gagal lagi karena window
  rate limit belum reset, jadi itu cuma membuang waktu/quota request.
- Error dibedakan jadi RETRYABLE (rate limit, timeout, server error 5xx,
  connection error) vs NON-RETRYABLE (auth error, invalid request/model
  name, dst). Error non-retryable langsung di-raise tanpa membuang waktu
  retry yang tidak akan pernah berhasil, dan pesan errornya jelas
  (misal "API key invalid") bukan tersembunyi di balik riwayat retry.

REASONING MODEL SUPPORT (ditambahkan setelah ditemukan di pemakaian nyata):
Beberapa model reasoning (DeepSeek-R1, QwQ, dan model lain yang diakses
lewat router/proxy seperti TokenRouter) menyertakan chain-of-thought di
DALAM field `content` itu sendiri, dibungkus tag <think>...</think>,
SEBELUM jawaban final. Tanpa pembersihan, blok <think> ini:
- Untuk complete_json: bisa membuat json.loads() gagal total (karena
  <think>...</think>{...json...} bukan JSON valid), atau dalam kasus
  lebih buruk DITERIMA sebagai bagian dari prompt analisis berikutnya.
- Untuk complete_text (dipakai ThreatModeler/ReportWriter): blok <think>
  ikut tertulis mentah-mentah ke laporan final -- inilah yang terjadi
  pada laporan nyata yang ditemukan saat penggunaan dengan router custom.
Beberapa provider/router menaruh reasoning di field terpisah
(`message.reasoning_content`) bukan di `content` -- _strip_think_blocks
menangani kasus tag-di-dalam-content; kasus field terpisah otomatis aman
karena kita hanya membaca `message.content`.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from openai import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    NotFoundError,
    OpenAI,
    PermissionDeniedError,
    RateLimitError,
)

from config import OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL, OPENAI_MODEL_FALLBACK

logger = logging.getLogger("bugbounty_ai.llm_client")

# Pola tag reasoning yang umum dipakai berbagai reasoning model. Daftar ini
# sengaja mencakup beberapa varian (bukan hanya <think>) karena provider
# berbeda kadang memakai tag berbeda untuk konsep yang sama.
_THINK_BLOCK_PATTERNS = [
    re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<thinking>.*?</thinking>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<reasoning>.*?</reasoning>", re.DOTALL | re.IGNORECASE),
]

# Kalau tag pembuka ada tapi tag penutup TIDAK ADA (terpotong karena
# max_tokens atau alasan lain), buang dari tag pembuka sampai akhir teks --
# lebih baik kehilangan sebagian output yang valid daripada membiarkan
# chain-of-thought yang terpotong bocor ke laporan.
_UNCLOSED_THINK_PATTERNS = [
    re.compile(r"<think>.*", re.DOTALL | re.IGNORECASE),
    re.compile(r"<thinking>.*", re.DOTALL | re.IGNORECASE),
    re.compile(r"<reasoning>.*", re.DOTALL | re.IGNORECASE),
]


def _strip_think_blocks(text: str) -> str:
    """
    Membuang blok chain-of-thought (<think>...</think> dan varian serupa)
    dari output model. Dipakai di SEMUA titik yang membaca `content` dari
    response -- baik untuk JSON (_call_once) maupun teks bebas
    (complete_text) -- supaya reasoning model lewat router manapun tidak
    mencemari hasil akhir, apa pun agent yang memanggilnya.
    """
    if not text or "<think" not in text.lower() and "<reasoning" not in text.lower():
        return text  # fast path: tidak ada indikasi tag reasoning sama sekali

    cleaned = text
    for pattern in _THINK_BLOCK_PATTERNS:
        cleaned = pattern.sub("", cleaned)

    # Setelah buang yang closed-tag, cek lagi apakah masih ada tag pembuka
    # tanpa penutup (kemungkinan terpotong oleh max_tokens).
    for pattern in _UNCLOSED_THINK_PATTERNS:
        cleaned = pattern.sub("", cleaned)

    return cleaned.strip()

# Error yang PANTAS di-retry -- biasanya transient (akan hilang sendiri
# kalau dicoba lagi setelah delay).
_RETRYABLE_EXCEPTIONS = (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError)

# Error yang TIDAK akan pernah berhasil meski di-retry -- retry hanya
# membuang waktu dan menyembunyikan pesan error yang sebenarnya jelas.
_NON_RETRYABLE_EXCEPTIONS = (AuthenticationError, BadRequestError, NotFoundError, PermissionDeniedError)

BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 20.0


class LLMClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ):
        """
        base_url: untuk memakai OpenAI resmi, biarkan None (default SDK).
        Untuk router/proxy OpenAI-compatible (TokenRouter, OpenRouter, dst),
        isi dengan endpoint mereka (atau set OPENAI_BASE_URL di .env --
        lihat config.py). Endpoint router HARUS compatible dengan format
        request/response OpenAI Chat Completions API (termasuk dukungan
        response_format={"type": "json_object"} yang dipakai complete_json
        di bawah) -- kalau router tidak mendukung structured JSON output,
        complete_json bisa gagal parsing meski request berhasil terkirim.
        """
        if not (api_key or OPENAI_API_KEY):
            raise RuntimeError(
                "OPENAI_API_KEY belum diset. Set environment variable OPENAI_API_KEY "
                "atau pass api_key= saat membuat LLMClient."
            )
        resolved_base_url = base_url or OPENAI_BASE_URL
        client_kwargs: dict[str, Any] = {"api_key": api_key or OPENAI_API_KEY}
        if resolved_base_url:
            client_kwargs["base_url"] = resolved_base_url
            logger.info("LLMClient memakai base_url custom: %s", resolved_base_url)

        self.client = OpenAI(**client_kwargs)
        self.model = model or OPENAI_MODEL
        self.fallback_model = OPENAI_MODEL_FALLBACK

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_retries: int = 3,
    ) -> dict[str, Any]:
        """
        Memanggil model dan mengharuskan output JSON valid.
        temperature rendah secara default -- ini tugas analisis teknis,
        bukan brainstorming kreatif, jadi kita ingin determinisme tinggi.

        Strategi retry:
        1. Coba model utama sampai `max_retries` kali, dengan exponential
           backoff antar percobaan -- TAPI hanya untuk error yang memang
           retryable (rate limit, timeout, server error). Error
           non-retryable (auth, bad request) langsung di-raise.
        2. Kalau model utama tetap gagal setelah semua retry (untuk error
           retryable) atau gagal karena model tidak ditemukan (NotFoundError
           -- bisa berarti nama model salah/deprecated), coba fallback
           model satu kali.
        3. Kalau keduanya gagal, raise dengan riwayat error lengkap.
        """
        try:
            return self._complete_json_with_retry(self.model, system_prompt, user_prompt, temperature, max_retries)
        except _NON_RETRYABLE_EXCEPTIONS as e:
            # NotFoundError sering berarti nama model salah/deprecated --
            # ini satu-satunya non-retryable error yang masuk akal dicoba
            # ulang dengan model LAIN (fallback), bukan diulang model sama.
            if isinstance(e, NotFoundError) and self.fallback_model:
                logger.warning(
                    "Model '%s' tidak ditemukan (mungkin nama salah/deprecated). Mencoba fallback '%s'.",
                    self.model,
                    self.fallback_model,
                )
                try:
                    return self._complete_json_with_retry(
                        self.fallback_model, system_prompt, user_prompt, temperature, max_retries=1
                    )
                except Exception as fallback_error:  # noqa: BLE001
                    raise RuntimeError(
                        f"Model utama '{self.model}' tidak ditemukan, DAN fallback "
                        f"'{self.fallback_model}' juga gagal: {fallback_error}"
                    ) from e
            # Auth/permission/bad-request error: tidak ada gunanya retry
            # atau fallback model lain -- raise langsung dengan pesan jelas.
            raise RuntimeError(
                f"Error non-retryable dari OpenAI API ({type(e).__name__}): {e}. "
                f"Periksa API key, format request, atau ketersediaan model."
            ) from e
        except Exception as primary_error:  # noqa: BLE001
            # Semua retry untuk model utama sudah habis (error retryable
            # yang persisten) -- coba fallback model sebagai upaya terakhir.
            if self.fallback_model:
                logger.warning(
                    "Model utama '%s' gagal setelah %d percobaan: %s. Mencoba fallback '%s'.",
                    self.model,
                    max_retries,
                    primary_error,
                    self.fallback_model,
                )
                try:
                    return self._complete_json_with_retry(
                        self.fallback_model, system_prompt, user_prompt, temperature, max_retries=1
                    )
                except Exception as fallback_error:  # noqa: BLE001
                    raise RuntimeError(
                        f"Model utama '{self.model}' gagal: {primary_error}. "
                        f"Fallback '{self.fallback_model}' juga gagal: {fallback_error}"
                    ) from primary_error
            raise RuntimeError(f"Gagal mendapatkan respons JSON valid dari LLM: {primary_error}") from primary_error

    def _complete_json_with_retry(
        self, model: str, system_prompt: str, user_prompt: str, temperature: float, max_retries: int
    ) -> dict[str, Any]:
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                return self._call_once(model, system_prompt, user_prompt, temperature)
            except _NON_RETRYABLE_EXCEPTIONS:
                # Jangan ditangkap di sini -- biarkan menjalar ke caller
                # (complete_json) supaya ditangani sebagai non-retryable,
                # tanpa membuang sisa percobaan retry yang tidak akan
                # pernah berhasil.
                raise
            except json.JSONDecodeError as e:
                last_error = e
                logger.warning(
                    "[%s] attempt %d/%d: JSON tidak valid dari model: %s",
                    model,
                    attempt + 1,
                    max_retries,
                    e,
                )
            except _RETRYABLE_EXCEPTIONS as e:
                last_error = e
                logger.warning(
                    "[%s] attempt %d/%d: error retryable (%s): %s",
                    model,
                    attempt + 1,
                    max_retries,
                    type(e).__name__,
                    e,
                )
            except Exception as e:  # noqa: BLE001
                # Error tidak dikenal -- treat sebagai retryable secara
                # konservatif (lebih aman mencoba lagi daripada langsung
                # gagal total untuk error yang belum dikategorikan), tapi
                # dicatat jelas jenisnya untuk debugging.
                last_error = e
                logger.warning(
                    "[%s] attempt %d/%d: error tidak terklasifikasi (%s): %s",
                    model,
                    attempt + 1,
                    max_retries,
                    type(e).__name__,
                    e,
                )

            if attempt < max_retries - 1:
                backoff = min(BASE_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
                logger.info("Menunggu %.1fs sebelum retry...", backoff)
                time.sleep(backoff)

        raise last_error if last_error else RuntimeError(f"Gagal memanggil model {model} tanpa error spesifik.")

    def _call_once(self, model: str, system_prompt: str, user_prompt: str, temperature: float) -> dict[str, Any]:
        response = self.client.chat.completions.create(
            model=model,
            temperature=temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = response.choices[0].message.content
        cleaned_content = _strip_think_blocks(content)
        if cleaned_content != content:
            logger.info(
                "Membuang reasoning block (<think> dst) dari response model '%s' "
                "sebelum parsing JSON -- terdeteksi reasoning model.",
                model,
            )
        return json.loads(cleaned_content)

    def complete_text(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_retries: int = 2
    ) -> str:
        """
        Sama seperti complete_json tapi untuk output teks bebas (dipakai
        ThreatModeler dan ReportWriter untuk narasi). Sekarang punya retry
        dengan backoff yang sama -- sebelumnya method ini tidak punya
        retry sama sekali, jadi satu network blip langsung menggagalkan
        seluruh panggilan tanpa percobaan ulang.
        """
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    temperature=temperature,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                )
                raw_content = response.choices[0].message.content or ""
                cleaned = _strip_think_blocks(raw_content)
                if cleaned != raw_content:
                    logger.info(
                        "Membuang reasoning block (<think> dst) dari response model '%s' "
                        "(complete_text) -- terdeteksi reasoning model.",
                        self.model,
                    )
                return cleaned
            except _NON_RETRYABLE_EXCEPTIONS as e:
                raise RuntimeError(f"Error non-retryable dari OpenAI API ({type(e).__name__}): {e}") from e
            except Exception as e:  # noqa: BLE001
                last_error = e
                if attempt < max_retries - 1:
                    backoff = min(BASE_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
                    logger.warning(
                        "complete_text attempt %d/%d gagal (%s), retry dalam %.1fs...",
                        attempt + 1,
                        max_retries,
                        type(e).__name__,
                        backoff,
                    )
                    time.sleep(backoff)

        raise RuntimeError(f"Gagal mendapatkan respons teks dari LLM setelah {max_retries} percobaan: {last_error}")
