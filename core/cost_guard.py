"""
core/cost_guard.py

Pencegahan biaya API yang tidak terkontrol.

Tanpa ini: repo besar bisa menghasilkan ratusan evidence dari scanner,
dan pipeline akan memanggil GPT untuk SEMUANYA tanpa peringatan atau
batas, baik untuk Vulnerability Hunter maupun False Positive Checker
(jadi sebenarnya 2x panggilan per evidence, plus Exploit Simulator untuk
yang confirmed). Ini risiko biaya nyata, bukan cuma soal kerapian kode.

Strategi MVP (sengaja sederhana, bukan token counting presisi):
- Cap jumlah evidence yang akan dianalisis per scan (default bisa
  di-override).
- Evidence yang terpotong karena cap diprioritaskan berdasarkan
  "seriousness" kasar dari rule_id (heuristik nama rule, BUKAN keputusan
  final -- itu tetap tugas GPT/scanner, ini hanya urutan triase).
- Beri estimasi biaya KASAR di awal (berdasarkan asumsi token rata-rata
  per evidence) supaya pengguna punya gambaran sebelum pipeline jalan
  jauh -- bukan angka presisi, hanya orientasi.
"""

from __future__ import annotations

import logging

from core.models import Evidence

logger = logging.getLogger("bugbounty_ai.cost_guard")

DEFAULT_MAX_EVIDENCE_PER_SCAN = 80

# Estimasi SANGAT kasar: setiap evidence melewati 2 pemanggilan LLM wajib
# (Vulnerability Hunter + False Positive Checker), masing-masing kira-kira
# 1500-2500 token gabungan (prompt + response) untuk kasus rata-rata.
# Ini BUKAN penghitungan token presisi (butuh tokenizer asli untuk itu),
# hanya untuk memberi gambaran kasar ke pengguna di awal.
ESTIMATED_TOKENS_PER_EVIDENCE = 4000

# Kata kunci dalam rule_id yang biasanya mengindikasikan severity tinggi --
# dipakai HANYA untuk urutan triase ketika harus memotong evidence yang
# melebihi cap, bukan keputusan severity final.
HIGH_PRIORITY_RULE_HINTS = [
    "reentrancy",
    "unprotected",
    "arbitrary",
    "delegatecall",
    "suicidal",
    "unchecked",
    "access-control",
    "sql",
    "rce",
    "ssrf",
    "injection",
    "auth",
]


class CostGuardResult:
    def __init__(self, evidences_to_process: list[Evidence], truncated_count: int, estimated_tokens: int):
        self.evidences_to_process = evidences_to_process
        self.truncated_count = truncated_count
        self.estimated_tokens = estimated_tokens


def apply_cost_guard(
    evidences: list[Evidence],
    max_evidence: int = DEFAULT_MAX_EVIDENCE_PER_SCAN,
) -> CostGuardResult:
    """
    Menerapkan cap jumlah evidence yang akan dianalisis GPT. Jika jumlah
    evidence melebihi cap, evidence diurutkan dulu berdasarkan heuristik
    prioritas (rule yang biasanya lebih serius didahulukan), lalu dipotong.

    Caller WAJIB menampilkan truncated_count ke pengguna -- jangan
    memotong secara senyap, supaya pengguna tahu ada evidence yang
    tidak dianalisis dan bisa menaikkan cap kalau perlu.
    """
    total = len(evidences)

    if total <= max_evidence:
        return CostGuardResult(
            evidences_to_process=evidences,
            truncated_count=0,
            estimated_tokens=total * ESTIMATED_TOKENS_PER_EVIDENCE,
        )

    sorted_evidences = sorted(evidences, key=_priority_score, reverse=True)
    kept = sorted_evidences[:max_evidence]
    truncated = total - max_evidence

    logger.warning(
        "Jumlah evidence (%d) melebihi cap (%d). %d evidence TIDAK akan dianalisis GPT "
        "pada scan ini (diprioritaskan berdasarkan heuristik rule yang biasanya lebih "
        "serius). Naikkan max_evidence kalau ingin menganalisis semuanya.",
        total,
        max_evidence,
        truncated,
    )

    return CostGuardResult(
        evidences_to_process=kept,
        truncated_count=truncated,
        estimated_tokens=max_evidence * ESTIMATED_TOKENS_PER_EVIDENCE,
    )


def _priority_score(evidence: Evidence) -> int:
    rule = (evidence.rule_id or "").lower()
    return sum(1 for hint in HIGH_PRIORITY_RULE_HINTS if hint in rule)
