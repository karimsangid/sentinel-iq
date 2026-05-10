"""SQLite storage for structured log entries."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from backend.models.log_entry import DashboardStats, LogType, NormalizedLog, Severity

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    message TEXT DEFAULT '',
    raw TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}',
    source_file TEXT DEFAULT '',
    log_type TEXT DEFAULT 'unknown',
    embedded INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);",
    "CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source);",
    "CREATE INDEX IF NOT EXISTS idx_logs_log_type ON logs(log_type);",
    "CREATE INDEX IF NOT EXISTS idx_logs_embedded ON logs(embedded);",
]


class LogDatabase:
    """SQLite wrapper for log storage with full CRUD and query capabilities."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(CREATE_TABLE)
            for idx_sql in CREATE_INDEXES:
                conn.execute(idx_sql)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Insert ────────────────────────────────────────────────────────

    def insert_log(self, log: NormalizedLog) -> str:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO logs
                   (id, timestamp, source, hostname, severity, message, raw, metadata, source_file, log_type, embedded)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    log.id,
                    log.timestamp.isoformat(),
                    log.source,
                    log.hostname,
                    log.severity.value,
                    log.message,
                    log.raw,
                    json.dumps(log.metadata),
                    log.source_file,
                    log.log_type.value,
                    int(log.embedded),
                ),
            )
        return log.id

    def insert_logs(self, logs: list[NormalizedLog]) -> int:
        with self._connect() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO logs
                   (id, timestamp, source, hostname, severity, message, raw, metadata, source_file, log_type, embedded)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        log.id,
                        log.timestamp.isoformat(),
                        log.source,
                        log.hostname,
                        log.severity.value,
                        log.message,
                        log.raw,
                        json.dumps(log.metadata),
                        log.source_file,
                        log.log_type.value,
                        int(log.embedded),
                    )
                    for log in logs
                ],
            )
        return len(logs)

    # ── Read ──────────────────────────────────────────────────────────

    def get_log(self, log_id: str) -> Optional[NormalizedLog]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM logs WHERE id = ?", (log_id,)).fetchone()
        return self._row_to_log(row) if row else None

    def search_logs(
        self,
        query: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        hostname: Optional[str] = None,
        log_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NormalizedLog]:
        conditions: list[str] = []
        params: list[Any] = []

        if query:
            conditions.append("message LIKE ?")
            params.append(f"%{query}%")
        if severity:
            conditions.append("severity = ?")
            params.append(severity.lower())
        if source:
            conditions.append("(source LIKE ? OR hostname LIKE ?)")
            params.extend([f"%{source}%", f"%{source}%"])
        if hostname:
            conditions.append("hostname LIKE ?")
            params.append(f"%{hostname}%")
        if log_type:
            conditions.append("log_type = ?")
            params.append(log_type.lower())
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM logs WHERE {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_log(r) for r in rows]

    def count_logs(self, severity: Optional[str] = None, source: Optional[str] = None) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity.lower())
        if source:
            conditions.append("source LIKE ?")
            params.append(f"%{source}%")
        where = " AND ".join(conditions) if conditions else "1=1"
        with self._connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) as cnt FROM logs WHERE {where}", params).fetchone()
        return row["cnt"] if row else 0

    def get_unembedded_logs(self, limit: int = 100) -> list[NormalizedLog]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM logs WHERE embedded = 0 ORDER BY timestamp ASC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_log(r) for r in rows]

    def mark_embedded(self, log_ids: list[str]) -> None:
        if not log_ids:
            return
        placeholders = ",".join("?" for _ in log_ids)
        with self._connect() as conn:
            conn.execute(f"UPDATE logs SET embedded = 1 WHERE id IN ({placeholders})", log_ids)

    # ── Statistics ────────────────────────────────────────────────────

    def get_stats(self) -> DashboardStats:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) as cnt FROM logs").fetchone()["cnt"]

            severity_counts = {}
            for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM logs GROUP BY severity"):
                severity_counts[row["severity"]] = row["cnt"]

            sources = [
                row["source"]
                for row in conn.execute("SELECT DISTINCT source FROM logs WHERE source != '' LIMIT 50")
            ]

            timeline = []
            for row in conn.execute(
                """SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                          severity, COUNT(*) as cnt
                   FROM logs
                   GROUP BY hour, severity
                   ORDER BY hour DESC
                   LIMIT 500"""
            ):
                timeline.append({"time": row["hour"], "severity": row["severity"], "count": row["cnt"]})

        return DashboardStats(
            total_logs=total,
            critical_count=severity_counts.get("critical", 0),
            high_count=severity_counts.get("high", 0),
            medium_count=severity_counts.get("medium", 0),
            low_count=severity_counts.get("low", 0),
            info_count=severity_counts.get("info", 0),
            sources=sources,
            timeline=timeline,
        )

    # ── Delete ────────────────────────────────────────────────────────

    def delete_log(self, log_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        return cursor.rowcount > 0

    def delete_all(self) -> int:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM logs")
        return cursor.rowcount

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _row_to_log(row: sqlite3.Row) -> NormalizedLog:
        return NormalizedLog(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source=row["source"],
            hostname=row["hostname"],
            severity=Severity(row["severity"]),
            message=row["message"],
            raw=row["raw"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            source_file=row["source_file"],
            log_type=LogType(row["log_type"]),
            embedded=bool(row["embedded"]),
        )
