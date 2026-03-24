"""SQLite-backed scan history storage.

Uses only the built-in ``sqlite3`` module — zero new dependencies.
Thread-safe: each public method opens its own connection so callers
from async (via ``run_in_executor``) and sync contexts both work.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SCHEMA = """\
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    service         TEXT NOT NULL,
    region          TEXT NOT NULL,
    status          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    total_findings      INTEGER DEFAULT 0,
    total_attack_paths  INTEGER DEFAULT 0,
    severity_critical   INTEGER DEFAULT 0,
    severity_high       INTEGER DEFAULT 0,
    severity_medium     INTEGER DEFAULT 0,
    severity_low        INTEGER DEFAULT 0,
    overall_health      TEXT,
    analysis_json   TEXT,
    error_message   TEXT
);
"""


class ScanStore:
    """Lightweight scan-history persistence backed by a single SQLite file."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        # Create the table on first use.
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # -- internal helpers -----------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return dict(row)

    # -- public API -----------------------------------------------------------

    def create_scan(self, *, id: str, session_id: str, service: str, region: str) -> dict[str, Any]:
        """Insert a new scan record in ``running`` state."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans (id, session_id, service, region, status, started_at) "
                "VALUES (?, ?, ?, ?, 'running', ?)",
                (id, session_id, service, region, now),
            )
        return {
            "id": id,
            "session_id": session_id,
            "service": service,
            "region": region,
            "status": "running",
            "started_at": now,
        }

    def complete_scan(self, id: str, analysis_json: str) -> None:
        """Mark a scan as completed and store the full analysis JSON.

        Summary fields (finding counts, severity breakdown, health) are
        extracted automatically from the JSON so ``list_scans`` can return
        them without deserialising the full blob.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Extract summary fields from the analysis JSON.
        total_findings = 0
        total_attack_paths = 0
        sev_c = sev_h = sev_m = sev_l = 0
        overall_health: str | None = None
        try:
            data = json.loads(analysis_json)
            summary = data.get("account_summary", {})
            total_findings = summary.get("total_findings", 0)
            total_attack_paths = summary.get("total_attack_paths", 0)
            breakdown = summary.get("severity_breakdown", {})
            sev_c = breakdown.get("CRITICAL", 0)
            sev_h = breakdown.get("HIGH", 0)
            sev_m = breakdown.get("MEDIUM", 0)
            sev_l = breakdown.get("LOW", 0)
            overall_health = summary.get("overall_health")
        except (json.JSONDecodeError, AttributeError):
            pass

        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status='completed', completed_at=?, analysis_json=?, "
                "total_findings=?, total_attack_paths=?, "
                "severity_critical=?, severity_high=?, severity_medium=?, severity_low=?, "
                "overall_health=? "
                "WHERE id=? AND status='running'",
                (
                    now,
                    analysis_json,
                    total_findings,
                    total_attack_paths,
                    sev_c,
                    sev_h,
                    sev_m,
                    sev_l,
                    overall_health,
                    id,
                ),
            )

    def fail_scan(self, id: str, error_message: str) -> None:
        """Mark a scan as failed."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status='failed', completed_at=?, error_message=? "
                "WHERE id=? AND status='running'",
                (now, error_message, id),
            )

    def cancel_scan(self, id: str, error_message: str) -> None:
        """Mark a single running scan as cancelled."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status='cancelled', completed_at=?, error_message=? "
                "WHERE id=? AND status='running'",
                (now, error_message, id),
            )

    def cancel_session(self, session_id: str, error_message: str) -> int:
        """Mark all running scans in a session as cancelled."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE scans SET status='cancelled', completed_at=?, error_message=? "
                "WHERE session_id=? AND status='running'",
                (now, error_message, session_id),
            )
        return cursor.rowcount

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent scan metadata (no ``analysis_json``) sorted newest-first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, session_id, service, region, status, started_at, completed_at, "
                "total_findings, total_attack_paths, severity_critical, severity_high, "
                "severity_medium, severity_low, overall_health, error_message "
                "FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, id: str) -> dict[str, Any] | None:
        """Return a full scan record including ``analysis_json``."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (id,)).fetchone()
        return self._row_to_dict(row)

    def delete_session(self, session_id: str) -> int:
        """Delete all scans belonging to *session_id*. Returns rows deleted."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE session_id=?", (session_id,))
        return cursor.rowcount
