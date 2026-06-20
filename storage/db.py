"""
storage/db.py

Storage layer berbasis SQLite untuk menyimpan hasil scan.

PERBAIKAN KONKURENSI (#23):
SQLite mendukung concurrent reads tapi hanya satu writer pada satu waktu.
Dua pendekatan dipakai sekaligus:

1. WAL mode (Write-Ahead Logging): diaktifkan sekali saat init. Ini
   memungkinkan pembaca tidak memblokir penulis dan sebaliknya -- jauh
   lebih cocok untuk use case ini (banyak read report, sesekali write
   dari scan baru) dibanding default journal mode.

2. Satu connection persistent per instance `FindingsDB` (bukan buat
   connection baru per method seperti sebelumnya). Ini menghindari
   overhead buka/tutup connection berulang, dan thread_local connection
   dengan `check_same_thread=False` + explicit locking via
   `threading.Lock` memastikan concurrent writes dari thread berbeda
   tidak menghasilkan "database is locked" error.

Catatan: untuk skalabilitas lebih jauh (banyak proses, bukan hanya
banyak thread), migrasi ke PostgreSQL adalah solusi tepat -- SQLite
dengan WAL tetap punya batasan untuk multi-process write concurrency.
Ini sudah cukup untuk CLI (satu proses) dan untuk service dengan
thread pool moderat (misal FastAPI dengan beberapa worker thread).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from core.models import ScanReport

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_path TEXT NOT NULL,
    repo_url TEXT,
    target_type TEXT,
    languages TEXT,
    scanners_used TEXT,
    generated_at TEXT NOT NULL,
    report_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_run_id INTEGER NOT NULL,
    title TEXT,
    category TEXT,
    severity TEXT,
    confidence REAL,
    file_path TEXT,
    function_name TEXT,
    validator_verdict TEXT,
    created_at TEXT,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_run ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(validator_verdict);
"""


class FindingsDB:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._lock = threading.Lock()
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """
        Mengembalikan connection yang thread-local (satu connection per
        thread, dibuat sekali dan di-reuse). Ini aman untuk concurrent
        reads antar thread. Untuk writes, caller WAJIB memakai self._lock
        (lihat save_report) supaya tidak ada dua thread yang write
        bersamaan -- WAL mode masih punya bottleneck satu writer.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # Timeout 30 detik: kalau write lock tidak bisa diperoleh
            # dalam 30 detik, raise exception daripada hang selamanya.
            conn.execute("PRAGMA busy_timeout = 30000")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.executescript(SCHEMA)
            conn.commit()

    def save_report(self, report: ScanReport) -> int:
        """Thread-safe write: hanya satu thread boleh write pada satu waktu."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    """INSERT INTO scan_runs
                       (target_path, repo_url, target_type, languages, scanners_used, generated_at, report_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        report.target.path,
                        report.target.repo_url,
                        report.target.target_type.value,
                        json.dumps(report.target.languages),
                        json.dumps(report.scanners_used),
                        report.generated_at.isoformat(),
                        report.model_dump_json(),
                    ),
                )
                scan_run_id = cursor.lastrowid

                for f in report.findings:
                    conn.execute(
                        """INSERT OR REPLACE INTO findings
                           (id, scan_run_id, title, category, severity, confidence,
                            file_path, function_name, validator_verdict, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            f.id,
                            scan_run_id,
                            f.title,
                            f.category.value,
                            f.severity.value,
                            f.confidence,
                            f.file_path,
                            f.function_name,
                            f.validator_verdict,
                            f.created_at.isoformat(),
                        ),
                    )
                conn.commit()
                return scan_run_id
            except Exception:
                conn.rollback()
                raise

    def list_runs(self) -> list[dict]:
        """Read-only: tidak perlu lock (WAL mode memungkinkan concurrent reads)."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, target_path, target_type, generated_at FROM scan_runs ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_report_json(self, scan_run_id: int) -> str | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT report_json FROM scan_runs WHERE id = ?", (scan_run_id,)
        ).fetchone()
        return row[0] if row else None

    def get_findings_by_severity(self, severity: str) -> list[dict]:
        """Query helper -- berguna untuk dashboard nanti."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY confidence DESC",
            (severity,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_confirmed_findings(self) -> list[dict]:
        """Semua finding confirmed lintas scan run -- berguna untuk trend analysis."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT f.*, s.target_path, s.generated_at as scan_date "
            "FROM findings f JOIN scan_runs s ON f.scan_run_id = s.id "
            "WHERE f.validator_verdict = 'confirmed' "
            "ORDER BY s.id DESC, f.confidence DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_reasoning_trail(self, scan_run_id: int, finding_id: str) -> list[dict] | None:
        """
        Ambil reasoning_trail untuk satu finding spesifik -- berguna untuk
        audit "kenapa GPT menyimpulkan ini" tanpa harus parse report_json
        penuh secara manual. report_json menyimpan seluruh ScanReport
        (termasuk reasoning_trail tiap finding) karena Finding.model_dump_json()
        menyertakan semua field, jadi tidak perlu kolom DB tambahan.
        """
        report_json = self.get_report_json(scan_run_id)
        if not report_json:
            return None

        report_data = json.loads(report_json)
        for f in report_data.get("findings", []):
            if f.get("id") == finding_id:
                return f.get("reasoning_trail", [])
        return None
