"""
core/pipeline.py

Orchestrator utama. Menjalankan alur penuh:

  RepoIndexer -> Scanners (Slither/Semgrep) -> ThreatModeler (overview)
  -> VulnerabilityHunter (evidence -> Finding) -> FalsePositiveChecker
  -> ExploitSimulator (PoC untuk yang confirmed) -> ReportWriter -> DB

Catatan desain: ini sengaja ditulis sebagai kelas Python biasa (bukan
LangGraph) supaya seluruh alur kontrol terlihat eksplisit dan mudah
di-debug langkah demi langkah. Migrasi ke LangGraph nanti straightforward
karena setiap method di sini sudah berbentuk "node" yang independen.
"""

from __future__ import annotations

import logging
from pathlib import Path

from agents.code_reader import CodeReader
from agents.exploit_simulator import ExploitSimulator
from agents.false_positive_checker import FalsePositiveChecker
from agents.report_writer import ReportWriter
from agents.threat_modeler import ThreatModeler
from agents.vulnerability_hunter import VulnerabilityHunter
from config import REPORTS_DIR, WORKDIR
from core.cost_guard import DEFAULT_MAX_EVIDENCE_PER_SCAN, apply_cost_guard
from core.dedup import deduplicate_evidence
from core.diff_analysis import DiffAnalyzer
from core.llm_client import LLMClient
from core.models import Evidence, ScanReport, ScanTarget, TargetType
from core.repo_indexer import RepoIndexer
from scanners.semgrep_runner import SemgrepScanner
from scanners.slither_runner import SlitherScanner
from scanners.zap_runner import ZapConfig, ZapScanner
from storage.db import FindingsDB

logger = logging.getLogger("bugbounty_ai.pipeline")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")


class AuditPipeline:
    def __init__(self, db_path: str, openai_api_key: str | None = None):
        self.indexer = RepoIndexer(workdir=WORKDIR)
        self.llm = LLMClient(api_key=openai_api_key)
        self.db = FindingsDB(db_path)

        self.scanners = [SlitherScanner(), SemgrepScanner()]

    def run(
        self,
        source: str,
        generate_poc: bool = True,
        generate_summary: bool = True,
        max_evidence: int = DEFAULT_MAX_EVIDENCE_PER_SCAN,
        diff_base_ref: str | None = None,
    ) -> ScanReport:
        logger.info("Loading target: %s", source)

        # Bersihkan sisa clone lama (>24 jam) dari run sebelumnya yang
        # mungkin crash/terinterupsi.
        removed = self.indexer.cleanup_stale_clones()
        if removed:
            logger.info("Membersihkan %d clone lama (>24 jam) dari workdir.", removed)

        target = self.indexer.load(source, need_full_history=bool(diff_base_ref))
        logger.info(
            "Target loaded. type=%s languages=%s path=%s",
            target.target_type.value,
            target.languages,
            target.path,
        )

        try:
            return self._run_pipeline(target, generate_poc, generate_summary, max_evidence, diff_base_ref)
        finally:
            # Selalu bersihkan direktori clone setelah selesai -- baik
            # sukses maupun exception di tengah jalan. Ini tidak dijalankan
            # untuk path lokal (lihat RepoIndexer.cleanup -- ia cek
            # target.repo_url is None dan langsung return).
            self.indexer.cleanup(target)

    def _run_pipeline(
        self,
        target: ScanTarget,
        generate_poc: bool,
        generate_summary: bool,
        max_evidence: int,
        diff_base_ref: str | None = None,
    ) -> ScanReport:
        files = self.indexer.list_relevant_files(target)
        logger.info("Found %d relevant files.", len(files))

        # --- Agent 2: Threat Modeler ---
        threat_modeler = ThreatModeler(self.llm)
        attack_surface_overview = threat_modeler.build_overview(target, files)

        # --- Scanners: kumpulkan evidence mentah ---
        all_evidence: list[Evidence] = []
        scanners_used: list[str] = []
        scanner_failures: list[str] = []

        for scanner in self.scanners:
            if not scanner.is_applicable(target.path, target.languages):
                continue
            logger.info("Running scanner: %s", scanner.name)
            try:
                evidences = scanner.run(target.path)
                logger.info("%s produced %d evidence item(s).", scanner.name, len(evidences))
                all_evidence.extend(evidences)
                scanners_used.append(scanner.name)
            except Exception as e:  # noqa: BLE001
                logger.error("Scanner %s GAGAL: %s", scanner.name, e)
                scanner_failures.append(f"{scanner.name}: {e}")

        if scanner_failures:
            logger.warning(
                "PERHATIAN: %d scanner gagal. Report TIDAK MENCAKUP analisis dari "
                "scanner yang gagal -- jangan diartikan sebagai 'kode bersih'.",
                len(scanner_failures),
            )

        if not all_evidence:
            logger.info("Tidak ada evidence dari scanner. Membuat report kosong.")
            report = ScanReport(target=target, findings=[], scanners_used=scanners_used)
            self._write_outputs(report, attack_surface_overview, scanner_failures=scanner_failures)
            return report

        # --- Dedup ---
        deduped_evidence = deduplicate_evidence(all_evidence)
        if len(deduped_evidence) < len(all_evidence):
            logger.info(
                "Dedup: %d evidence -> %d setelah digabung.",
                len(all_evidence), len(deduped_evidence),
            )

        # --- Diff-aware filtering (opsional) ---
        # Kalau diff_base_ref diberikan, fokuskan analisis HANYA ke evidence
        # yang menyentuh file yang berubah dari base_ref -- signal-to-noise
        # jauh lebih baik untuk menemukan bug yang baru diintroduksi di
        # upgrade/patch, dibanding selalu scan ulang seluruh codebase.
        diff_excluded_count = 0
        if diff_base_ref:
            try:
                diff_analyzer = DiffAnalyzer(target.path)
                changed_files = diff_analyzer.get_changed_files(diff_base_ref)
                logger.info(
                    "Diff mode: %d file berubah antara '%s' dan HEAD.",
                    len(changed_files), diff_base_ref,
                )
                deduped_evidence, diff_excluded_count = diff_analyzer.filter_evidence_to_changed_files(
                    deduped_evidence, changed_files
                )
                if diff_excluded_count:
                    logger.info(
                        "Diff mode: %d evidence di-skip karena berada di file yang TIDAK berubah.",
                        diff_excluded_count,
                    )
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Diff mode gagal (%s) -- melanjutkan dengan full scan tanpa filter diff.", e
                )

        # --- Cost guard ---
        guard_result = apply_cost_guard(deduped_evidence, max_evidence=max_evidence)
        if guard_result.truncated_count > 0:
            logger.warning(
                "%d evidence TIDAK dianalisis (melebihi cap max_evidence=%d).",
                guard_result.truncated_count, max_evidence,
            )
        logger.info("Estimasi kasar token: ~%d", guard_result.estimated_tokens)

        # --- Agent 1 + 3: Code Reader + Vulnerability Hunter ---
        code_reader = CodeReader(repo_root=target.path)
        hunter = VulnerabilityHunter(
            self.llm, code_reader, repo_root=target.path, target_type=target.target_type.value
        )
        logger.info("Analyzing %d evidence item(s) with GPT...", len(guard_result.evidences_to_process))
        # Bahasa utama target dipakai untuk cross-file context resolution
        # (import statement syntax berbeda per bahasa). Untuk repo
        # multi-bahasa, ambil bahasa pertama yang terdeteksi -- ini
        # heuristik sederhana, cross-file context untuk file di bahasa
        # lain akan di-skip secara anggun (tidak crash, hanya tidak ada
        # context tambahan untuk file itu).
        primary_language = target.languages[0] if target.languages else ""
        findings = hunter.analyze_batch(guard_result.evidences_to_process, language=primary_language)

        # --- Agent 5: False Positive Checker ---
        fp_checker = FalsePositiveChecker(self.llm, code_reader=code_reader)
        logger.info("Running false-positive validation on %d finding(s)...", len(findings))
        findings = fp_checker.validate_batch(findings)

        confirmed_count = sum(1 for f in findings if f.validator_verdict == "confirmed")
        logger.info("Validation complete. %d/%d confirmed.", confirmed_count, len(findings))

        # --- Agent 4: Exploit Simulator ---
        if generate_poc:
            simulator = ExploitSimulator(self.llm)
            findings = [simulator.simulate(f) for f in findings]

        report = ScanReport(target=target, findings=findings, scanners_used=scanners_used)

        # --- Agent 6: Report Writer ---
        self._write_outputs(
            report,
            attack_surface_overview,
            generate_summary=generate_summary,
            scanner_failures=scanner_failures,
            truncated_count=guard_result.truncated_count,
        )

        # --- Simpan ke DB ---
        self.db.save_report(report)

        return report

    def _write_outputs(
        self,
        report: ScanReport,
        attack_surface_overview: str,
        generate_summary: bool = True,
        scanner_failures: list[str] | None = None,
        truncated_count: int = 0,
    ) -> None:
        writer = ReportWriter(self.llm if generate_summary else None)
        repo_name = Path(report.target.path).name
        output_path = REPORTS_DIR / f"{repo_name}_report.md"

        content = writer.write_markdown(report, str(output_path))

        caveats = []
        if scanner_failures:
            failures_list = "\n".join(f"- {f}" for f in scanner_failures)
            caveats.append(
                f"**PERHATIAN -- Scanner Gagal:** Scan berikut GAGAL dijalankan dan "
                f"TIDAK tercakup dalam report ini (jangan diartikan sebagai 'tidak ada bug'):\n{failures_list}"
            )
        if truncated_count > 0:
            caveats.append(
                f"**PERHATIAN -- Evidence Terpotong:** {truncated_count} evidence dari scanner "
                f"TIDAK dianalisis pada scan ini karena melebihi cost guard cap. "
                f"Jalankan ulang dengan `max_evidence` lebih besar untuk mencakup semuanya."
            )

        caveats_block = ("\n\n" + "\n\n".join(caveats) + "\n\n") if caveats else "\n\n"

        # Sisipkan attack surface overview + caveats ke awal file (setelah
        # header ringkasan), tanpa mengubah logika report_writer.
        final_content = content.replace(
            "## Confirmed Findings",
            f"{caveats_block}## Attack Surface Overview\n\n{attack_surface_overview}\n\n## Confirmed Findings",
        )
        Path(output_path).write_text(final_content, encoding="utf-8")
        logger.info("Report written to: %s", output_path)

    def run_dynamic_scan(
        self,
        target_url: str,
        confirm_authorized: bool,
        zap_api_url: str = "http://localhost:8080",
        zap_api_key: str = "",
        generate_summary: bool = True,
    ) -> ScanReport:
        """
        Dynamic scan terhadap aplikasi web yang BENAR-BENAR BERJALAN (live),
        memakai OWASP ZAP. Ini method TERPISAH dari run() (static scan) karena:
        - Input-nya URL target, bukan path repo/source code.
        - Butuh konfirmasi otorisasi eksplisit (confirm_authorized) -- lihat
          peringatan keras di scanners/zap_runner.py.
        - Tidak ada cross-file context atau diff mode (konsep itu spesifik
          source code statis, tidak relevan untuk dynamic scan).

        Evidence dari ZAP dianalisis dengan agent yang SAMA (Vulnerability
        Hunter, False Positive Checker) seperti static scan -- konsisten
        secara arsitektur: scanner nyata dulu, GPT menganalisis evidence-nya,
        bukan GPT menebak sendiri.

        Catatan: VulnerabilityHunter.analyze() membaca snippet kode dari
        file lokal (code_reader.py) untuk evidence statis -- untuk evidence
        ZAP, "file_path" sebenarnya berisi URL endpoint, bukan path file,
        jadi code_reader akan gagal resolve path (is_reliable=False) dan
        finding otomatis masuk needs_human_review. Ini BENAR secara desain:
        evidence ZAP dianalisis berdasarkan raw_message-nya (deskripsi alert
        ZAP) tanpa snippet kode, bukan dipaksa mencari source code yang
        sebenarnya tidak relevan untuk dynamic finding.
        """
        zap_config = ZapConfig(zap_api_url=zap_api_url, api_key=zap_api_key)
        zap = ZapScanner(config=zap_config)

        logger.info("Memulai dynamic scan (OWASP ZAP) terhadap: %s", target_url)
        evidences = zap.run(target_url, confirm_authorized=confirm_authorized)
        logger.info("ZAP menghasilkan %d evidence.", len(evidences))

        # ScanTarget sintetis untuk merepresentasikan target dynamic scan --
        # path diisi dengan URL karena tidak ada path filesystem yang relevan.
        target = ScanTarget(
            path=target_url,
            repo_url=None,
            target_type=TargetType.WEB_BACKEND,
            languages=[],
        )

        if not evidences:
            report = ScanReport(target=target, findings=[], scanners_used=["owasp_zap"])
            self._write_outputs(report, "_(Dynamic scan -- tidak ada attack surface overview, lihat alert ZAP langsung.)_")
            return report

        # Reuse VulnerabilityHunter -- code_reader tetap dibuat meski tidak
        # akan banyak berguna di sini (file_path evidence ZAP adalah URL,
        # bukan path lokal), supaya alur analisis konsisten dengan static scan.
        code_reader = CodeReader(repo_root=".")
        hunter = VulnerabilityHunter(self.llm, code_reader, target_type=target.target_type.value)
        findings = hunter.analyze_batch(evidences)

        fp_checker = FalsePositiveChecker(self.llm, code_reader=code_reader)
        findings = fp_checker.validate_batch(findings)

        confirmed_count = sum(1 for f in findings if f.validator_verdict == "confirmed")
        logger.info("Dynamic scan validation complete. %d/%d confirmed.", confirmed_count, len(findings))

        report = ScanReport(target=target, findings=findings, scanners_used=["owasp_zap"])
        self._write_outputs(
            report,
            "_(Dynamic scan terhadap target live -- attack surface overview tidak relevan, "
            "lihat daftar endpoint yang di-spider ZAP di laporan ZAP asli kalau diperlukan.)_",
            generate_summary=generate_summary,
        )
        self.db.save_report(report)
        return report
