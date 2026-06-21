"""
cli.py

Entry point command-line.

Setup (sekali saja):
    cp .env.example .env
    # edit .env, isi OPENAI_API_KEY=sk-...

Contoh pemakaian:
    python cli.py scan https://github.com/org/some-defi-protocol
    python cli.py scan ./local-repo-path
    python cli.py scan ./local-repo-path --no-poc
    python cli.py list-runs

Catatan: OPENAI_API_KEY juga bisa diset lewat environment variable
langsung (`export OPENAI_API_KEY=sk-...`) sebagai alternatif file .env --
environment variable yang sudah diset manual selalu diutamakan di atas
isi file .env (lihat config.py).
"""

from __future__ import annotations

import argparse
import sys

from config import DB_PATH, validate_config
from core.pipeline import AuditPipeline


def cmd_scan(args: argparse.Namespace) -> None:
    pipeline = AuditPipeline(db_path=DB_PATH)
    report = pipeline.run(
        source=args.target,
        generate_poc=not args.no_poc,
        generate_summary=not args.no_summary,
        max_evidence=args.max_evidence,
        diff_base_ref=args.diff_base,
    )

    confirmed = [f for f in report.findings if f.validator_verdict == "confirmed"]
    print("\n=== SCAN SELESAI ===")
    print(f"Target        : {report.target.path}")
    print(f"Total findings: {len(report.findings)}")
    print(f"Confirmed     : {len(confirmed)}")

    import pathlib

    repo_name = pathlib.Path(report.target.path).name
    print(f"Report        : reports/{repo_name}_report.md")

    if args.bounty_format and confirmed:
        from core.bounty_report_format import format_finding_for_platform

        out_path = pathlib.Path("reports") / f"{repo_name}_{args.bounty_format}_submissions.md"
        sections = [
            f"# Submission Drafts -- Format: {args.bounty_format}",
            "",
            "_PERINGATAN: ini adalah draft yang dihasilkan otomatis untuk membantu Anda menyusun "
            "submission, BUKAN siap kirim langsung. Selalu verifikasi PoC benar-benar jalan, "
            "cek scope program, dan sesuaikan dengan panduan submission TERBARU dari platform "
            "sebelum mengirim._",
            "",
            "---",
            "",
        ]
        for f in confirmed:
            sections.append(format_finding_for_platform(f, args.bounty_format))
            sections.append("\n---\n")
        out_path.write_text("\n".join(sections), encoding="utf-8")
        print(f"Submission drafts ({args.bounty_format}): {out_path}")


def cmd_scan_dynamic(args: argparse.Namespace) -> None:
    pipeline = AuditPipeline(db_path=DB_PATH)
    report = pipeline.run_dynamic_scan(
        target_url=args.target_url,
        confirm_authorized=args.i_have_authorization,
        zap_api_url=args.zap_api_url,
        zap_api_key=args.zap_api_key,
        generate_summary=not args.no_summary,
    )

    confirmed = [f for f in report.findings if f.validator_verdict == "confirmed"]
    print("\n=== DYNAMIC SCAN SELESAI ===")
    print(f"Target        : {report.target.path}")
    print(f"Total findings: {len(report.findings)}")
    print(f"Confirmed     : {len(confirmed)}")

    import pathlib

    repo_name = pathlib.Path(report.target.path).name or "dynamic_target"
    print(f"Report        : reports/{repo_name}_report.md")


def cmd_list_runs(args: argparse.Namespace) -> None:
    from storage.db import FindingsDB

    db = FindingsDB(DB_PATH)
    runs = db.list_runs()
    if not runs:
        print("Belum ada scan run tersimpan.")
        return
    for r in runs:
        print(f"#{r['id']:<4} {r['generated_at']:<25} {r['target_type']:<15} {r['target_path']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bugbounty-ai",
        description="AI agent untuk Bug Bounty / Smart Contract Audit / Web Security Assessment.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Jalankan audit terhadap repo/path target.")
    scan_parser.add_argument("target", help="URL git atau path lokal target.")
    scan_parser.add_argument(
        "--no-poc", action="store_true", help="Skip pembuatan PoC oleh Exploit Simulator."
    )
    scan_parser.add_argument(
        "--no-summary", action="store_true", help="Skip pembuatan executive summary via GPT."
    )
    scan_parser.add_argument(
        "--max-evidence",
        type=int,
        default=80,
        help="Batas jumlah evidence yang dianalisis GPT per scan (cost guard). Default: 80.",
    )
    scan_parser.add_argument(
        "--bounty-format",
        choices=["hackerone", "immunefi", "code4rena"],
        default=None,
        help="Generate draft submission tambahan dalam format platform tertentu, "
        "untuk finding yang confirmed.",
    )
    scan_parser.add_argument(
        "--diff-base",
        type=str,
        default=None,
        help="Fokuskan scan hanya ke file yang berubah dari ref ini (branch/tag/commit), "
        "dibandingkan dengan HEAD. Contoh: --diff-base v1.2.0. Butuh target berupa "
        "git repository. Signal-to-noise lebih baik untuk audit upgrade/patch.",
    )
    scan_parser.set_defaults(func=cmd_scan)

    list_parser = sub.add_parser("list-runs", help="Lihat riwayat scan yang tersimpan di DB.")
    list_parser.set_defaults(func=cmd_list_runs)

    dynamic_parser = sub.add_parser(
        "scan-dynamic",
        help="Dynamic scan (OWASP ZAP) terhadap target URL yang BENAR-BENAR BERJALAN.",
    )
    dynamic_parser.add_argument(
        "target_url", help="URL target yang sudah running, contoh: http://localhost:3000"
    )
    dynamic_parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help=(
            "WAJIB diset eksplisit. Menyatakan Anda sudah memiliki otorisasi untuk "
            "menjalankan active scan (mengirim traffic uji nyata) terhadap target ini -- "
            "baik karena ini environment lokal/development milik Anda sendiri, atau "
            "target sudah dikonfirmasi dalam scope program bug bounty resmi. Tanpa flag "
            "ini, scan akan ditolak."
        ),
    )
    dynamic_parser.add_argument(
        "--zap-api-url",
        default="http://localhost:8080",
        help="URL API ZAP daemon yang sudah berjalan. Default: http://localhost:8080",
    )
    dynamic_parser.add_argument(
        "--zap-api-key", default="", help="API key ZAP, kalau daemon dikonfigurasi memerlukannya."
    )
    dynamic_parser.add_argument(
        "--no-summary", action="store_true", help="Skip pembuatan executive summary via GPT."
    )
    dynamic_parser.set_defaults(func=cmd_scan_dynamic)

    args = parser.parse_args()

    if args.command in ("scan", "scan-dynamic"):
        problems, warnings_list = validate_config(check_scanners=(args.command == "scan"))
        if problems:
            print("=== KONFIGURASI BELUM LENGKAP ===", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            print(file=sys.stderr)
            print("Setup cepat: cp .env.example .env, lalu edit .env", file=sys.stderr)
            sys.exit(1)
        if warnings_list:
            print("=== PERINGATAN (tidak menghentikan scan) ===", file=sys.stderr)
            for w in warnings_list:
                print(f"  - {w}", file=sys.stderr)
            print(file=sys.stderr)

    try:
        args.func(args)
    except Exception as e:  # noqa: BLE001
        print(f"\n[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
