"""
Storage layer — sqlite-backed for account, subscription, and scan ownership.
"""

from __future__ import annotations

import csv
import io
import json
import secrets
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
                    phone TEXT NOT NULL DEFAULT '',
                    business_address TEXT NOT NULL DEFAULT '',
                    referral_source TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    type TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_waitlist_leads_email ON waitlist_leads(email);
                CREATE INDEX IF NOT EXISTS ix_waitlist_leads_created ON waitlist_leads(created_at);

                CREATE TABLE IF NOT EXISTS password_accounts (
                    user_sub TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_sub) REFERENCES users(auth_sub) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS ix_password_accounts_email ON password_accounts(email);
                """
            )
        # Must run outside the block above: Lock is not reentrant.
        self._ensure_waitlist_extra_columns()
        self._ensure_users_authorized_column()
        self._ensure_user_name_columns()
        self._ensure_guest_scan_columns()
        self._ensure_guest_daily_table()

    def _ensure_guest_scan_columns(self) -> None:
        with self._lock, self._conn:
            cols = {
                row[1] for row in self._conn.execute("PRAGMA table_info(scans)").fetchall()
            }
            if "guest_poll_token" not in cols:
                self._conn.execute("ALTER TABLE scans ADD COLUMN guest_poll_token TEXT")

    def _ensure_guest_daily_table(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS guest_daily_scans (
                    guest_key TEXT NOT NULL,
                    day_utc TEXT NOT NULL,
                    scan_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (guest_key, day_utc)
                )
                """
            )

    def _ensure_user_name_columns(self) -> None:
        with self._lock, self._conn:
            cols = {
                row[1] for row in self._conn.execute("PRAGMA table_info(users)").fetchall()
            }
            if "first_name" not in cols:
                self._conn.execute(
                    "ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT ''"
                )
            if "last_name" not in cols:
                self._conn.execute(
                    "ALTER TABLE users ADD COLUMN last_name TEXT NOT NULL DEFAULT ''"
                )

    def _ensure_users_authorized_column(self) -> None:
        """Add users.authorized for account approval / allowlisting."""
        with self._lock, self._conn:
            cols = {
                row[1] for row in self._conn.execute("PRAGMA table_info(users)").fetchall()
            }
            if "authorized" not in cols:
                self._conn.execute(
                    "ALTER TABLE users ADD COLUMN authorized INTEGER NOT NULL DEFAULT 1"
                )

    def _ensure_waitlist_extra_columns(self) -> None:
        """Migrate older DBs that lack extended signup columns."""
        need = [
            ("phone", "TEXT NOT NULL DEFAULT ''"),
            ("business_address", "TEXT NOT NULL DEFAULT ''"),
            ("referral_source", "TEXT NOT NULL DEFAULT ''"),
        ]
        with self._lock, self._conn:
            have = {
                row[1]
                for row in self._conn.execute("PRAGMA table_info(waitlist_leads)").fetchall()
            }
            for col, decl in need:
                if col not in have:
                    self._conn.execute(
                        f"ALTER TABLE waitlist_leads ADD COLUMN {col} {decl}"
                    )

    def append_waitlist(
        self,
        email: str,
        *,
        name: str = "",
        phone: str = "",
        business_address: str = "",
        referral_source: str = "",
        source: str = "",
        entry_type: str = "",
        created_at: Optional[datetime] = None,
    ) -> None:
        ts = _to_iso(created_at or datetime.now(timezone.utc))
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO waitlist_leads (
                  email, name, phone, business_address, referral_source, source, type, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    name,
                    phone,
                    business_address,
                    referral_source,
                    source,
                    entry_type,
                    ts,
                ),
            )

    def export_waitlist_csv(self) -> str:
        """RFC-style CSV; utf-8 BOM may be added by the HTTP handler for Excel."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "email",
                "name",
                "phone",
                "business_address",
                "referral_source",
                "source",
                "type",
                "created_at",
            ]
        )
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT email, name, phone, business_address, referral_source,
                       source, type, created_at
                FROM waitlist_leads ORDER BY id ASC
                """
            ).fetchall()
        for row in rows:
            writer.writerow(
                [
                    row["email"],
                    row["name"],
                    row["phone"],
                    row["business_address"],
                    row["referral_source"],
                    row["source"],
                    row["type"],
                    row["created_at"],
                ]
            )
        return buf.getvalue()

    def ensure_user(
        self,
        auth_sub: str,
        email: Optional[str] = None,
        *,
        authorized_override: Optional[bool] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> None:
        now = _to_iso(datetime.now(timezone.utc))
        if authorized_override is None:
            auth_int = settings.initial_authorized_as_int(email)
        else:
            auth_int = 1 if authorized_override else 0
        fn = (first_name or "").strip()[:100]
        ln = (last_name or "").strip()[:100]
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO users (auth_sub, email, created_at, authorized, first_name, last_name)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(auth_sub) DO UPDATE SET
                  email=COALESCE(excluded.email, users.email),
                  first_name=CASE WHEN excluded.first_name != '' THEN excluded.first_name ELSE users.first_name END,
                  last_name=CASE WHEN excluded.last_name != '' THEN excluded.last_name ELSE users.last_name END
                """,
                (auth_sub, email, now, auth_int, fn, ln),
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
        guest_poll_token: Optional[str] = None,
    ):
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO scans
                  (scan_id, owner_sub, target, scan_type, depth, status, progress, findings_count, risk_score, risk_tier, submitted_at, completed_at, error, guest_poll_token)
                VALUES
                  (?, ?, ?, ?, ?, 'queued', 0, 0, NULL, NULL, ?, NULL, NULL, ?)
                """,
                (
                    scan_id,
                    owner_sub,
                    target,
                    scan_type,
                    depth,
                    _to_iso(submitted_at),
                    guest_poll_token,
                ),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO findings (scan_id, findings_json) VALUES (?, '[]')",
                (scan_id,),
            )

    def try_acquire_guest_scan_slot(self, guest_key: str) -> bool:
        """
        Reserve one guest scan for this UTC calendar day. Returns False if quota exceeded.
        """
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        limit = max(1, int(settings.guest_scans_per_utc_day))
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT scan_count FROM guest_daily_scans WHERE guest_key = ? AND day_utc = ?",
                (guest_key, day),
            ).fetchone()
            used = int(row[0]) if row else 0
            if used >= limit:
                return False
            if row:
                self._conn.execute(
                    """
                    UPDATE guest_daily_scans SET scan_count = scan_count + 1
                    WHERE guest_key = ? AND day_utc = ?
                    """,
                    (guest_key, day),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO guest_daily_scans (guest_key, day_utc, scan_count)
                    VALUES (?, ?, 1)
                    """,
                    (guest_key, day),
                )
        return True

    def guest_poll_token_matches(self, scan_id: str, token: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT guest_poll_token FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if not row or row[0] is None:
            return False
        try:
            return secrets.compare_digest(str(row[0]), str(token))
        except (TypeError, ValueError):
            return False

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

    def get_password_account_by_email(self, email: str) -> Optional[Dict[str, str]]:
        """Return user_sub and Argon2 hash for normalized email, if registered."""
        norm = email.strip().lower()
        with self._lock:
            row = self._conn.execute(
                "SELECT user_sub, password_hash FROM password_accounts WHERE email = ?",
                (norm,),
            ).fetchone()
        if not row:
            return None
        return {"user_sub": row["user_sub"], "password_hash": row["password_hash"]}

    def get_user(self, auth_sub: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE auth_sub = ?", (auth_sub,)
            ).fetchone()
        return dict(row) if row else None

    def get_auth_sub_by_email(self, email: str) -> Optional[str]:
        em = email.strip().lower()
        with self._lock:
            row = self._conn.execute(
                "SELECT auth_sub FROM users WHERE lower(coalesce(email,'')) = ?",
                (em,),
            ).fetchone()
        return str(row["auth_sub"]) if row else None

    def set_account_authorized(self, auth_sub: str, authorized: bool) -> None:
        v = 1 if authorized else 0
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE users SET authorized = ? WHERE auth_sub = ?",
                (v, auth_sub),
            )

    def register_password_account(self, user_sub: str, email: str, password_hash: str) -> None:
        now = _to_iso(datetime.now(timezone.utc))
        em = email.strip().lower()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO password_accounts (user_sub, email, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (user_sub, em, password_hash, now),
            )


store = _SQLiteStore()