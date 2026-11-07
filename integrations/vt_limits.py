"""Persistent shared VirusTotal request limits."""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone

import os
from pathlib import Path

DB_PATH = Path(os.getenv("AEGISTRACE_DB_PATH", "data/aegistrace.db"))

MAX_PER_MINUTE = 4
MAX_PER_DAY = 550


def reserve_request() -> tuple[bool, str | None]:
    """Atomically reserve one real outbound API request."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    utc_day = datetime.now(timezone.utc).date().isoformat()

    with sqlite3.connect(DB_PATH, timeout=15) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_request_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_at REAL NOT NULL,
                utc_day TEXT NOT NULL
            )
        """)

        # Serialize competing requests before checking either limit.
        conn.execute("BEGIN IMMEDIATE")
        minute_count = conn.execute(
            "SELECT COUNT(*) FROM vt_request_usage WHERE requested_at > ?",
            (now - 60,),
        ).fetchone()[0]

        day_count = conn.execute(
            "SELECT COUNT(*) FROM vt_request_usage WHERE utc_day = ?",
            (utc_day,),
        ).fetchone()[0]

        if day_count >= MAX_PER_DAY:
            conn.rollback()
            return False, "daily_quota_exceeded"

        if minute_count >= MAX_PER_MINUTE:
            conn.rollback()
            return False, "minute_rate_limit"

        conn.execute(
            "INSERT INTO vt_request_usage(requested_at, utc_day) VALUES(?, ?)",
            (now, utc_day),
        )
        conn.commit()

    return True, None
