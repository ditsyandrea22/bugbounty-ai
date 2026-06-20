"""
core/bounty_report_format.py

Format report yang disesuaikan ke template platform bug bounty nyata,
bukan hanya Markdown generik.

MASALAH YANG DIPECAHKAN:
Laporan yang formatnya tidak sesuai standar platform sering DI-REJECT
bukan karena bug-nya salah, tapi karena penyajian tidak memenuhi
ekspektasi triager:
- HackerOne mengharapkan "Steps to Reproduce" yang step-by-step
  (numbered list aksi konkret), bukan narasi paragraf
- Immunefi mengharapkan estimasi impact finansial dan PoC yang bisa
  langsung dijalankan (forge test)
- Code4rena punya format markdown dengan severity justification yang
  mengikuti kriteria mereka sendiri

CATATAN PENTING: format di bawah adalah PENDEKATAN ke struktur yang
umum diminta platform-platform tersebut per pengetahuan umum -- bukan
template resmi yang di-scrape langsung dari platform. SELALU cek
panduan submission TERBARU dari program spesifik yang dituju sebelum
submit, karena format bisa berubah dan tiap program punya field
custom sendiri.
"""

from __future__ import annotations

from core.models import Finding


def format_for_hackerone(finding: Finding) -> str:
    """
    HackerOne mengharapkan struktur: Summary, Steps to Reproduce (numbered,
    konkret), Impact, Supporting Material. Steps to Reproduce HARUS berupa
    aksi yang bisa diikuti triager satu per satu -- bukan narasi.
    """
    steps = _narrative_to_steps(finding.exploit_scenario.narrative if finding.exploit_scenario else "")

    lines = [
        f"## Summary",
        f"{finding.title}",
        "",
        f"**Severity:** {finding.severity.value}",
        f"**Weakness:** {finding.category.value}",
        "",
        "## Steps to Reproduce",
        "",
    ]
    if steps:
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
    else:
        lines.append("_(Belum ada steps terstruktur -- lihat Root Cause dan Exploit Scenario di bawah, "
                      "perlu disusun ulang manual menjadi langkah numbered sebelum submit.)_")
        lines.append("")
        lines.append(f"Root Cause: {finding.root_cause}")

    lines += [
        "",
        "## Impact",
        finding.impact or "_(tidak tersedia)_",
        "",
        "## Supporting Material/References",
        f"- File: `{finding.file_path}`" + (f", Function: `{finding.function_name}`" if finding.function_name else ""),
        f"- Lines: {finding.line_start}-{finding.line_end}" if finding.line_start else "",
    ]

    if finding.exploit_scenario and finding.exploit_scenario.poc_code:
        lines += [
            "",
            f"### PoC ({finding.exploit_scenario.poc_type})",
            f"```\n{finding.exploit_scenario.poc_code}\n```",
        ]

    lines += [
        "",
        "## Suggested Fix",
        finding.recommendation or "_(tidak tersedia)_",
    ]

    return "\n".join(line for line in lines if line is not None)


def format_for_immunefi(finding: Finding) -> str:
    """
    Immunefi (smart contract bug bounty) mengharapkan: deskripsi teknis,
    impact dengan estimasi finansial bila memungkinkan, PoC yang bisa
    dijalankan (forge test), dan severity justification berdasarkan
    kriteria Immunefi (lihat core/severity_rubric.py).
    """
    lines = [
        f"## {finding.title}",
        "",
        f"**Severity:** {finding.severity.value}",
        f"**Vulnerability Category:** {finding.category.value}",
        f"**Confidence:** {finding.confidence:.2f}",
        "",
        "### Description",
        finding.root_cause or "_(tidak tersedia)_",
        "",
        "### Impact",
        finding.impact or "_(tidak tersedia)_",
        "",
        "_(Catatan: estimasi impact finansial dalam USD/token amount perlu "
        "dilengkapi manual berdasarkan TVL protokol saat ini -- AI tidak punya "
        "akses ke data on-chain real-time untuk menghitung ini secara akurat.)_",
        "",
        "### Severity Justification",
        (finding.validation_notes or "_(lihat rubrik severity untuk justifikasi kategori ini)_"),
        "",
        "### Proof of Concept",
    ]

    if finding.exploit_scenario and finding.exploit_scenario.poc_code:
        lines += [
            f"PoC type: `{finding.exploit_scenario.poc_type}` -- jalankan dengan `forge test` "
            f"di environment lokal/fork sebelum submit, untuk memverifikasi PoC benar-benar berhasil.",
            "",
            f"```solidity\n{finding.exploit_scenario.poc_code}\n```",
        ]
    else:
        lines.append(
            "_(PoC belum tersedia -- PENTING: Immunefi mengharapkan PoC yang bisa dijalankan. "
            "Jangan submit tanpa PoC yang sudah diverifikasi jalan, atau severity klaim akan "
            "diragukan triager.)_"
        )

    lines += [
        "",
        "### Recommended Mitigation",
        finding.recommendation or "_(tidak tersedia)_",
    ]

    return "\n".join(lines)


def format_for_code4rena(finding: Finding) -> str:
    """
    Code4rena (audit contest) mengharapkan format: Impact, Proof of Concept,
    Tools Used, Recommended Mitigation -- dengan severity berdasarkan
    kriteria C4 sendiri (High/Medium, jarang pakai Critical/Low secara
    terpisah seperti platform lain).
    """
    # C4 secara konvensi memetakan severity ke hanya 2 tier utama
    c4_severity = "High" if finding.severity.value in ("Critical", "High") else "Medium"

    lines = [
        f"## [{c4_severity}] {finding.title}",
        "",
        "### Impact",
        finding.impact or "_(tidak tersedia)_",
        "",
        "### Proof of Concept",
        finding.root_cause or "_(tidak tersedia)_",
    ]

    if finding.exploit_scenario:
        lines += ["", finding.exploit_scenario.narrative]
        if finding.exploit_scenario.poc_code:
            lines += ["", f"```solidity\n{finding.exploit_scenario.poc_code}\n```"]

    lines += [
        "",
        "### Tools Used",
        "Manual review" + (
            f" + {', '.join({e.source_tool for e in finding.evidence})}" if finding.evidence else ""
        ),
        "",
        "### Recommended Mitigation Steps",
        finding.recommendation or "_(tidak tersedia)_",
    ]

    return "\n".join(lines)


_FORMATTERS = {
    "hackerone": format_for_hackerone,
    "immunefi": format_for_immunefi,
    "code4rena": format_for_code4rena,
}


def format_finding_for_platform(finding: Finding, platform: str) -> str:
    formatter = _FORMATTERS.get(platform.lower())
    if formatter is None:
        raise ValueError(
            f"Platform '{platform}' tidak dikenal. Pilihan: {list(_FORMATTERS.keys())}"
        )
    return formatter(finding)


def _narrative_to_steps(narrative: str) -> list[str]:
    """
    Heuristik sederhana untuk memecah narasi exploit_scenario jadi langkah
    numbered. Mencari kalimat yang dimulai dengan kata kerja aksi atau
    sudah ada angka/urutan di narasi GPT.
    """
    if not narrative:
        return []

    # Coba split berdasarkan numbered list yang mungkin sudah ada di narasi
    import re

    numbered = re.split(r"\n?\d+[.)]\s+", narrative)
    numbered = [s.strip() for s in numbered if s.strip()]
    if len(numbered) > 1:
        return numbered

    # Fallback: split per kalimat sebagai approximation langkah
    sentences = re.split(r"(?<=[.!?])\s+", narrative)
    return [s.strip() for s in sentences if s.strip() and len(s.strip()) > 10]
