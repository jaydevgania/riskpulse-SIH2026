from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.services.ledger import GENESIS_HASH, hash_report, verify_chain


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialise(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    revenue_band TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    ale_inr INTEGER NOT NULL,
                    likelihood_band TEXT NOT NULL,
                    exposure_inr INTEGER NOT NULL,
                    p_breach REAL NOT NULL,
                    report_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    integrity_payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_scans_domain_created ON scans(domain, created_at);
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    finding_key TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    signal TEXT NOT NULL,
                    narrative TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    points INTEGER NOT NULL,
                    dpdp_clause TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS selected_controls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    control_key TEXT NOT NULL,
                    control_name TEXT NOT NULL,
                    cost_inr INTEGER NOT NULL,
                    ale_reduction_inr INTEGER NOT NULL,
                    relevance TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monitoring_subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    revenue_band TEXT NOT NULL,
                    interval_minutes INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_run_at TEXT
                );
                """
            )

    def save_scan(self, result: dict[str, Any]) -> dict[str, Any]:
        created_at = datetime.now(UTC).isoformat()
        domain = result["domain"]
        payload = {
            "domain": domain,
            "revenue_band": result["revenue_band"],
            "created_at": created_at,
            "signals": result["signals"],
            "scoring": result["scoring"],
            "quantified": result["quantified"],
            "optimisation": result["optimisation"],
            "board_report": result["board_report"],
        }
        with self._connect() as db:
            previous = db.execute(
                "SELECT report_hash FROM scans WHERE domain = ? ORDER BY id DESC LIMIT 1", (domain,)
            ).fetchone()
            prev_hash = previous["report_hash"] if previous else GENESIS_HASH
            report_hash = hash_report(payload, prev_hash)
            cursor = db.execute(
                """
                INSERT INTO scans (
                    domain, revenue_band, created_at, score, ale_inr, likelihood_band,
                    exposure_inr, p_breach, report_hash, prev_hash, integrity_payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    domain,
                    result["revenue_band"],
                    created_at,
                    result["scoring"]["score"],
                    result["quantified"]["ale_inr"],
                    result["quantified"]["likelihood_band"],
                    result["quantified"]["exposure_inr"],
                    result["quantified"]["p_breach"],
                    report_hash,
                    prev_hash,
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            scan_id = int(cursor.lastrowid)
            db.executemany(
                """
                INSERT INTO findings (
                    scan_id, finding_key, severity, signal, narrative, recommendation, points, dpdp_clause
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        item["id"],
                        item["severity"],
                        item["signal"],
                        item["narrative"],
                        item["recommendation"],
                        item["points"],
                        item["dpdp_clause"],
                    )
                    for item in result["scoring"]["findings"]
                ],
            )
            db.executemany(
                """
                INSERT INTO selected_controls (
                    scan_id, control_key, control_name, cost_inr, ale_reduction_inr, relevance
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        item["id"],
                        item["name"],
                        item["cost_inr"],
                        item["ale_reduction_inr"],
                        item["relevance"],
                    )
                    for item in result["optimisation"]["selected"]
                ],
            )
        return {"scan_id": scan_id, "created_at": created_at, "report_hash": report_hash, "prev_hash": prev_hash}

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as db:
            record = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if record is None:
            return None
        payload = json.loads(record["integrity_payload_json"])
        payload.update(
            {
                "scan_id": record["id"],
                "report_hash": record["report_hash"],
                "prev_hash": record["prev_hash"],
            }
        )
        return payload

    def trend(self, domain: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id, created_at, score, ale_inr, likelihood_band FROM scans WHERE domain = ? ORDER BY id ASC",
                (domain,),
            ).fetchall()
        return [
            {
                "scan_id": row["id"],
                "ts": row["created_at"],
                "score": row["score"],
                "ale_inr": row["ale_inr"],
                "likelihood_band": row["likelihood_band"],
            }
            for row in rows
        ]

    def verify_ledger(self, domain: str) -> dict[str, Any]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id, prev_hash, report_hash, integrity_payload_json FROM scans WHERE domain = ? ORDER BY id ASC",
                (domain,),
            ).fetchall()
        records = [
            {
                "id": row["id"],
                "prev_hash": row["prev_hash"],
                "report_hash": row["report_hash"],
                "integrity_payload": json.loads(row["integrity_payload_json"]),
            }
            for row in rows
        ]
        return verify_chain(records)

    def upsert_monitoring(self, domain: str, revenue_band: str, interval_minutes: int) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO monitoring_subscriptions (domain, revenue_band, interval_minutes, enabled, created_at)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    revenue_band = excluded.revenue_band,
                    interval_minutes = excluded.interval_minutes,
                    enabled = 1
                """,
                (domain, revenue_band, interval_minutes, now),
            )
            row = db.execute("SELECT * FROM monitoring_subscriptions WHERE domain = ?", (domain,)).fetchone()
        return self._monitoring_row(row)

    def list_monitoring(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM monitoring_subscriptions"
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY domain"
        with self._connect() as db:
            rows = db.execute(query).fetchall()
        return [self._monitoring_row(row) for row in rows]

    def set_monitoring(self, monitoring_id: int, enabled: bool) -> dict[str, Any] | None:
        with self._connect() as db:
            db.execute("UPDATE monitoring_subscriptions SET enabled = ? WHERE id = ?", (int(enabled), monitoring_id))
            row = db.execute("SELECT * FROM monitoring_subscriptions WHERE id = ?", (monitoring_id,)).fetchone()
        return self._monitoring_row(row) if row else None

    def mark_monitoring_run(self, monitoring_id: int) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE monitoring_subscriptions SET last_run_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), monitoring_id),
            )

    @staticmethod
    def _monitoring_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "domain": row["domain"],
            "revenue_band": row["revenue_band"],
            "interval_minutes": row["interval_minutes"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "last_run_at": row["last_run_at"],
        }
