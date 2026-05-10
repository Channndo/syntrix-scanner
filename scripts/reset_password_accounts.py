#!/usr/bin/env python3
"""
Remove all email/password accounts (auth_sub like 'local:%') and their scans.
Preserves guest:* users, guest scans, and waitlist data.

Usage (from scanner repo, with same SYNTRIX_SQLITE_PATH as the API):
  PYTHONPATH=. python scripts/reset_password_accounts.py --yes

On Render: download the SQLite file or run in a one-off shell with the mounted DB path.
"""

from __future__ import annotations

import argparse
import os
import sys

# Repo root = parent of scripts/
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.storage import store  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description="Delete all local: password accounts and their scans.")
    p.add_argument("--yes", action="store_true", help="Required to actually delete data.")
    args = p.parse_args()
    if not args.yes:
        print("Refusing to run without --yes (destructive).")
        sys.exit(1)

    pat = "local:%"
    with store._lock, store._conn:
        c = store._conn
        c.execute(
            "DELETE FROM findings WHERE scan_id IN (SELECT scan_id FROM scans WHERE owner_sub LIKE ?)",
            (pat,),
        )
        c.execute("DELETE FROM scans WHERE owner_sub LIKE ?", (pat,))
        c.execute("DELETE FROM subscriptions WHERE auth_sub LIKE ?", (pat,))
        c.execute("DELETE FROM password_accounts WHERE user_sub LIKE ?", (pat,))
        c.execute("DELETE FROM users WHERE auth_sub LIKE ?", (pat,))
        c.commit()

    print(
        "Done: removed all local: password accounts, subscriptions, and their scans. "
        "Guest and waitlist rows were left intact."
    )


if __name__ == "__main__":
    main()
