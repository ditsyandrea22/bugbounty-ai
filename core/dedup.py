"""
core/dedup.py

Deduplikasi Evidence SEBELUM dikirim ke GPT.

Tanpa ini: kalau dua scanner (atau dua rule dari scanner yang sama)
menandai baris yang sama persis, sistem akan membuat 2+ Finding terpisah
untuk satu bug yang sama. Ini merusak kredibilitas report (terlihat
"menemukan banyak bug" padahal duplikat) dan membuang biaya API.

Strategi: kelompokkan evidence berdasarkan (file_path, overlapping line
range). Evidence dalam satu kelompok yang overlap akan digabung jadi satu
representative evidence yang membawa SEMUA raw_message dari sumber asli,
supaya GPT tetap melihat konteks gabungan -- bukan kehilangan informasi
begitu saja.
"""

from __future__ import annotations

from core.models import Evidence

# Berapa baris toleransi untuk dianggap "lokasi sama" antar evidence
# yang line range-nya tidak identik tapi berdekatan/overlap.
LINE_OVERLAP_TOLERANCE = 2


def _ranges_overlap(a_start: int | None, a_end: int | None, b_start: int | None, b_end: int | None) -> bool:
    if a_start is None or b_start is None:
        return False
    a_end = a_end or a_start
    b_end = b_end or b_start
    return (a_start - LINE_OVERLAP_TOLERANCE) <= b_end and (b_start - LINE_OVERLAP_TOLERANCE) <= a_end


def deduplicate_evidence(evidences: list[Evidence]) -> list[Evidence]:
    """
    Mengembalikan list evidence yang sudah dideduplikasi. Evidence yang
    menunjuk file + line range yang overlap digabung menjadi satu entry
    gabungan, dengan raw_message berisi gabungan semua sumber asli.
    """
    by_file: dict[str, list[Evidence]] = {}
    for ev in evidences:
        by_file.setdefault(ev.file_path, []).append(ev)

    deduped: list[Evidence] = []

    for file_path, file_evidences in by_file.items():
        clusters: list[list[Evidence]] = []

        for ev in file_evidences:
            placed = False
            for cluster in clusters:
                representative = cluster[0]
                if _ranges_overlap(
                    representative.line_start, representative.line_end, ev.line_start, ev.line_end
                ):
                    cluster.append(ev)
                    placed = True
                    break
            if not placed:
                clusters.append([ev])

        for cluster in clusters:
            if len(cluster) == 1:
                deduped.append(cluster[0])
            else:
                deduped.append(_merge_cluster(cluster))

    return deduped


def _merge_cluster(cluster: list[Evidence]) -> Evidence:
    primary = cluster[0]
    sources_desc = "; ".join(f"[{e.source_tool}:{e.rule_id}] {e.raw_message}" for e in cluster)

    line_starts = [e.line_start for e in cluster if e.line_start is not None]
    line_ends = [e.line_end for e in cluster if e.line_end is not None]

    return Evidence(
        source_tool="+".join(sorted({e.source_tool for e in cluster})),
        rule_id="+".join(sorted({e.rule_id for e in cluster if e.rule_id})),
        file_path=primary.file_path,
        line_start=min(line_starts) if line_starts else primary.line_start,
        line_end=max(line_ends) if line_ends else primary.line_end,
        function_name=primary.function_name or next((e.function_name for e in cluster if e.function_name), None),
        raw_message=f"[DIGABUNG DARI {len(cluster)} TEMUAN PADA LOKASI SAMA] {sources_desc}",
        raw_output={"merged_from": [e.raw_output for e in cluster if e.raw_output]},
    )
