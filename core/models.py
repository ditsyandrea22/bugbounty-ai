"""
core/models.py

Skema data inti yang dipakai di seluruh pipeline.
Semua agent berkomunikasi lewat objek-objek ini (bukan string bebas),
supaya output GPT bisa divalidasi secara struktural (Pydantic) dan
tidak mudah "ngarang" field yang tidak diharapkan.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    """
    Pengganti datetime.utcnow() yang deprecated di Python 3.12+.
    datetime.utcnow() menghasilkan naive datetime (tanpa info timezone),
    yang sudah ditandai deprecated oleh Python sendiri -- gunakan
    datetime.now(timezone.utc) yang aware.
    """
    return datetime.now(timezone.utc)


# Batas ukuran raw_output (JSON mentah dari scanner) yang disimpan per
# Evidence. Output AST lengkap dari Slither/Semgrep bisa sangat besar untuk
# repo kompleks -- tanpa cap, report_json di SQLite bisa menggembung tanpa
# kontrol untuk repo dengan banyak finding. 8KB per evidence cukup untuk
# audit trail tanpa menyimpan seluruh AST node yang tidak perlu.
MAX_RAW_OUTPUT_CHARS = 8000


class ValidatorVerdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class TargetType(str, Enum):
    SMART_CONTRACT = "smart_contract"
    WEB_BACKEND = "web_backend"
    UNKNOWN = "unknown"


class VulnCategory(str, Enum):
    REENTRANCY = "Reentrancy"
    ACCESS_CONTROL = "Access Control"
    INTEGER_OVERFLOW = "Integer Overflow/Underflow"
    FRONT_RUNNING = "Front Running"
    ORACLE_MANIPULATION = "Oracle Manipulation"
    FLASH_LOAN_ATTACK = "Flash Loan Attack"
    LOGIC_BUG = "Logic Bug"
    AUTH_BYPASS = "Authentication Bypass"
    SSRF = "SSRF"
    SQLI = "SQL Injection"
    RCE = "Remote Code Execution"
    XSS = "Cross-Site Scripting"
    CSRF = "CSRF"
    IDOR = "IDOR"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DELEGATECALL_ABUSE = "Delegatecall Abuse"
    SIGNATURE_REPLAY = "Signature Replay"
    UNCHECKED_EXTERNAL_CALL = "Unchecked External Call"
    OTHER = "Other"


class Evidence(BaseModel):
    """
    Bukti mentah dari scanner nyata (Slither/Semgrep/dst).
    Ini SUMBER KEBENARAN -- GPT tidak boleh membuat finding tanpa
    setidaknya satu Evidence yang menunjuk ke sini.
    """

    source_tool: str  # "slither", "semgrep", "manual", dst
    rule_id: Optional[str] = None
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    raw_message: str
    raw_output: Optional[dict] = None  # JSON mentah asli dari tool, untuk audit trail

    @field_validator("raw_output")
    @classmethod
    def _cap_raw_output_size(cls, v: Optional[dict]) -> Optional[dict]:
        """
        Cap ukuran raw_output supaya tidak menggembungkan storage tanpa
        kontrol untuk repo dengan banyak finding kompleks. Kalau melebihi
        batas, simpan versi terpotong dengan flag yang jelas -- bukan
        dibuang diam-diam (audit trail tetap ada, hanya dipersingkat).
        """
        if v is None:
            return v
        import json as _json

        serialized = _json.dumps(v)
        if len(serialized) <= MAX_RAW_OUTPUT_CHARS:
            return v
        return {
            "_truncated": True,
            "_original_size_chars": len(serialized),
            "_preview": serialized[:MAX_RAW_OUTPUT_CHARS],
        }


class ExploitScenario(BaseModel):
    narrative: str = Field(..., description="Langkah-langkah skenario eksploitasi dalam bahasa natural")
    preconditions: list[str] = Field(default_factory=list)
    poc_code: Optional[str] = Field(
        None,
        description="Kode PoC HANYA untuk environment lokal/sandbox (contoh: forge test). "
        "Tidak boleh berisi target endpoint live.",
    )
    poc_type: Optional[str] = Field(None, description="contoh: 'foundry_test', 'local_repro_script'")


class Finding(BaseModel):
    model_config = {
        # PENTING: tanpa ini, Pydantic v2 hanya memvalidasi field saat objek
        # dikonstruksi -- assignment langsung setelahnya (misal
        # `finding.validator_verdict = raw_string_dari_gpt`) TIDAK akan
        # divalidasi ulang terhadap Literal/constraint lain. Karena seluruh
        # pipeline ini banyak melakukan assignment pasca-konstruksi
        # (false_positive_checker, vulnerability_hunter, exploit_simulator
        # semuanya mutate Finding yang sudah ada), validate_assignment WAJIB
        # True agar proteksi level-schema benar-benar berlaku, bukan cuma
        # ilusi keamanan di constructor saja.
        "validate_assignment": True
    }

    id: str  # uuid
    title: str
    category: VulnCategory
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0, description="Keyakinan model, 0-1")
    file_path: str
    function_name: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    root_cause: str
    impact: str
    exploit_scenario: Optional[ExploitScenario] = None
    recommendation: str

    evidence: list[Evidence] = Field(default_factory=list)

    # Hasil tahap False Positive Checker
    is_validated: bool = False
    validation_notes: Optional[str] = None
    # Sebelumnya Optional[str] bebas -- typo/variasi string dari LLM bisa
    # lolos tanpa terdeteksi di level schema. Literal memaksa nilai yang
    # masuk benar-benar salah satu dari tiga pilihan sah, dijaga Pydantic
    # sendiri, bukan hanya bergantung pada satu titik validasi manual di
    # false_positive_checker.py.
    validator_verdict: Optional[Literal["confirmed", "likely_false_positive", "needs_human_review"]] = None

    # AUDIT TRAIL: menyimpan ringkasan reasoning di tiap tahap pipeline
    # (Vulnerability Hunter, False Positive Checker, Exploit Simulator),
    # supaya bisa ditelusuri kembali KENAPA GPT menyimpulkan sesuatu --
    # sebelumnya hanya hasil akhir (Finding) yang tersimpan, chain-of-thought
    # yang menghasilkannya hilang begitu pipeline selesai. Ini penting untuk
    # justifikasi severity saat submission bug bounty, dan untuk debugging
    # kalau suatu finding terlihat salah.
    reasoning_trail: list["ReasoningStep"] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=_utcnow)


class ReasoningStep(BaseModel):
    """Satu langkah reasoning dari satu agent, untuk audit trail."""

    agent: str  # "vulnerability_hunter" | "false_positive_checker" | "exploit_simulator"
    summary: str  # ringkasan singkat keputusan/reasoning di tahap ini
    raw_response: Optional[dict] = None  # JSON response mentah dari LLM, untuk audit penuh
    timestamp: datetime = Field(default_factory=_utcnow)

    @field_validator("raw_response")
    @classmethod
    def _cap_raw_response_size(cls, v: Optional[dict]) -> Optional[dict]:
        if v is None:
            return v
        import json as _json

        serialized = _json.dumps(v)
        if len(serialized) <= MAX_RAW_OUTPUT_CHARS:
            return v
        return {"_truncated": True, "_preview": serialized[:MAX_RAW_OUTPUT_CHARS]}


class ScanTarget(BaseModel):
    path: str  # path lokal setelah clone
    repo_url: Optional[str] = None
    target_type: TargetType = TargetType.UNKNOWN
    languages: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    target: ScanTarget
    findings: list[Finding] = Field(default_factory=list)
    summary: Optional[str] = None
    scanners_used: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=_utcnow)

    def sorted_by_severity(self) -> list[Finding]:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(self.findings, key=lambda f: order[f.severity])


# Finding mereferensikan ReasoningStep (didefinisikan setelahnya) lewat
# forward reference string "ReasoningStep" -- model_rebuild() WAJIB
# dipanggil supaya Pydantic v2 me-resolve forward reference itu dengan
# benar setelah kedua class selesai didefinisikan. Tanpa ini, instansiasi
# Finding akan gagal dengan PydanticUndefinedAnnotation.
Finding.model_rebuild()
