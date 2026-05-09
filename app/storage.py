"""
Storage layer — sqlite-backed for account, subscription, and scan ownership.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional

from app.config import settings


def _to_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _from_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value)


class _SQLiteStore:
    def __init__(self):
        self._lock = Lock()
        self._conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS users (
                    auth_sub TEXT PRIMARY KEY,
                    email TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS subscriptions (
                    auth_sub TEXT PRIMARY KEY,
                    stripe_customer_id TEXT,
                    stripe_subscription_id TEXT,
                    plan_id TEXT,
                    status TEXT NOT NULL DEFAULT 'inactive',
                    current_period_end TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (auth_sub) REFERENCES users(auth_sub) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    owner_sub TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    depth TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    risk_score INTEGER,
                    risk_tier TEXT,
                    submitted_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    FOREIGN KEY (owner_sub) REFERENCES users(auth_sub) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS findings (
                    scan_id TEXT PRIMARY KEY,
                    findings_json TEXT NOT NULL DEFAULT '[]',
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS waitlist_leads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    type TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_waitlist_leads_email ON waitlist_leads(email);
                CREATE INDEX IF NOT EXISTS ix_waitlist_leads_created ON waitlist_leads(created_at);
                """
            )

    def append_waitlist(
        self,
        email: str,
        *,
        name: str = "",
        source: str = "",
        entry_type: str = "",
        created_at: Optional[datetime] = None,
    ) -> None:
        ts = _to_iso(created_at or datetime.now(timezone.utc))
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO waitlist_leads (email, name, source, type, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (email, name, source, entry_type, ts),
            )

    def ensure_user(self, auth_sub: str, email: Optional[str] = None) -> None:
        now = _to_iso(datetime.now(timezone.utc))
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO users (auth_sub, email, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(auth_sub) DO UPDATE SET email=COALESCE(excluded.email, users.email)
                """,
                (auth_sub, email, now),
            )

            self._conn.execute(
                """
                INSERT INTO subscriptions (auth_sub, status, updated_at)
                VALUES (?, 'inactive', ?)
                ON CONFLICT(auth_sub) DO NOTHING
                """,
                (auth_sub, now),
            )

    def create_scan(
        self,
        scan_id: str,
        owner_sub: str,
        target: str,
        scan_type: str,
        depth: str,
        submitted_at: datetime,
    ):
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO scans
                  (scan_id, owner_sub, target, scan_type, depth, status, progress, findings_count, risk_score, risk_tier, submitted_at, completed_at, error)
                VALUES
                  (?, ?, ?, ?, ?, 'queued', 0, 0, NULL, NULL, ?, NULL, NULL)
                """,
                (scan_id, owner_sub, target, scan_type, depth, _to_iso(submitted_at)),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO findings (scan_id, findings_json) VALUES (?, '[]')",
                (scan_id,),
            )

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return {
            "scan_id": row["scan_id"],
            "owner_sub": row["owner_sub"],
            "target": row["target"],
            "scan_type": row["scan_type"],
            "depth": row["depth"],
            "status": row["status"],
            "progress": row["progress"],
            "findings_count": row["findings_count"],
            "risk_score": row["risk_score"],
            "risk_tier": row["risk_tier"],
            "submitted_at": _from_iso(row["submitted_at"]),
            "completed_at": _from_iso(row["completed_at"]),
            "error": row["error"],
        }

    def update_status(self, scan_id: str, status: str, progress: int = 0):
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status = ?, progress = ? WHERE scan_id = ?",
                (status, progress, scan_id),
            )

    def save_findings(self, scan_id: str, findings: List[Dict[str, Any]]):
        payload = json.dumps(findings)
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE findings SET findings_json = ? WHERE scan_id = ?",
                (payload, scan_id),
            )
            self._conn.execute(
                "UPDATE scans SET findings_count = ? WHERE scan_id = ?",
                (len(findings), scan_id),
            )

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT findings_json FROM findings WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if not row:
            return []
        return json.loads(row["findings_json"])

    def get_summary(self, scan_id: str) -> Dict[str, int]:
        findings = self.get_findings(scan_id)
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in summary:
                summary[sev] += 1
        return summary

    def complete_scan(self, scan_id: str, risk_score: int, risk_tier: str, completed_at: datetime):
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE scans
                SET status = 'complete',
                    progress = 100,
                    risk_score = ?,
                    risk_tier = ?,
                    completed_at = ?
                WHERE scan_id = ?
                """,
                (risk_score, risk_tier, _to_iso(completed_at), scan_id),
            )

    def fail_scan(self, scan_id: str, error: str):
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status = 'failed', error = ? WHERE scan_id = ?",
                (error, scan_id),
            )

    def is_scan_owner(self, scan_id: str, auth_sub: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT owner_sub FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return bool(row and row["owner_sub"] == auth_sub)

    def set_subscription(
        self,
        auth_sub: str,
        status: str,
        stripe_customer_id: Optional[str] = None,
        stripe_subscription_id: Optional[str] = None,
        plan_id: Optional[str] = None,
        current_period_end: Optional[datetime] = None,
    ) -> None:
        self.ensure_user(auth_sub)
        now = _to_iso(datetime.now(timezone.utc))
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE subscriptions
                SET status = ?,
                    stripe_customer_id = COALESCE(?, stripe_customer_id),
                    stripe_subscription_id = COALESCE(?, stripe_subscription_id),
                    plan_id = COALESCE(?, plan_id),
                    current_period_end = COALESCE(?, current_period_end),
                    updated_at = ?
                WHERE auth_sub = ?
                """,
                (
                    status,
                    stripe_customer_id,
                    stripe_subscription_id,
                    plan_id,
                    _to_iso(current_period_end),
                    now,
                    auth_sub,
                ),
            )

    def get_subscription(self, auth_sub: str) -> Dict[str, Any]:
        self.ensure_user(auth_sub)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM subscriptions WHERE auth_sub = ?",
                (auth_sub,),
            ).fetchone()
        if not row:
            return {"status": "inactive"}
        return dict(row)

    def get_auth_sub_for_customer(self, stripe_customer_id: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT auth_sub FROM subscriptions WHERE stripe_customer_id = ?",
                (stripe_customer_id,),
            ).fetchone()
        return row["auth_sub"] if row else None


store = _SQLiteStore()