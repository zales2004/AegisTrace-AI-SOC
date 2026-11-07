"""Persistent, shared VirusTotal lookup scheduler for AegisTrace."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from integrations.virustotal import DB_PATH, lookup_ip, lookup_file_hash, get_cached_result

MAX_PER_MINUTE = 4
MAX_PER_DAY = 550
POLL_SECONDS = 1

PRIORITIES = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "file": 4,
}

_lock = threading.RLock()
_stop = threading.Event()
_thread: threading.Thread | None = None
_cooldown_until = 0.0


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def initialize():
    with _connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS vt_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            indicator TEXT NOT NULL,
            priority INTEGER NOT NULL,
            created_at REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            result_json TEXT,
            updated_at REAL NOT NULL,
            UNIQUE(kind, indicator)
        );

        CREATE TABLE IF NOT EXISTS vt_dispatches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dispatched_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vt_daily_usage (
            utc_day TEXT PRIMARY KEY,
            requests INTEGER NOT NULL DEFAULT 0
        );
        """)
        conn.commit()


def _utc_day():
    return datetime.now(timezone.utc).date().isoformat()


def enqueue(kind: str, indicator: str, priority: str = "low") -> dict:
    """Queue a lookup; do not make an HTTP request in this function."""
    initialize()
    kind = str(kind).strip().lower()
    indicator = str(indicator).strip().lower()
    priority = str(priority).strip().lower()

    if kind not in {"ip", "file"}:
        return {"status": "rejected", "reason": "invalid_kind"}
    if priority not in PRIORITIES:
        priority = "low"
    if not indicator:
        return {"status": "rejected", "reason": "empty_indicator"}

    now = time.time()
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, status, priority FROM vt_jobs WHERE kind=? AND indicator=?",
            (kind, indicator),
        ).fetchone()

        if row:
            # Keep the best priority if the same IP appears in multiple alerts.
            new_priority = min(int(row["priority"]), PRIORITIES[priority])
            conn.execute(
                """UPDATE vt_jobs SET priority=?,
                   updated_at=? WHERE id=?""",
                (new_priority, now, row["id"]),
            )
            conn.commit()
            return {
                "job_id": row["id"],
                "status": row["status"],
                "priority": new_priority,
            }

        cursor = conn.execute(
            """INSERT INTO vt_jobs
               (kind, indicator, priority, created_at, status, updated_at)
               VALUES (?, ?, ?, ?, 'pending', ?)""",
            (kind, indicator, PRIORITIES[priority], now, now),
        )
        conn.commit()
        return {
            "job_id": cursor.lastrowid,
            "status": "pending",
            "priority": PRIORITIES[priority],
        }


def get_result(kind: str, indicator: str) -> dict:
    initialize()
    with _connect() as conn:
        row = conn.execute(
            """SELECT status, result_json, priority, created_at, updated_at
               FROM vt_jobs WHERE kind=? AND indicator=?""",
            (kind, str(indicator).strip().lower()),
        ).fetchone()

    if not row:
        return {"status": "not_queued", "available": False}

    result = None
    if row["result_json"]:
        try:
            result = json.loads(row["result_json"])
        except (ValueError, TypeError):
            result = None

    return {
        "status": row["status"],
        "available": bool(result and result.get("available")),
        "result": result,
        "priority": row["priority"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _usage_today(conn):
    """Count actual outbound VirusTotal request reservations for today."""
    row = conn.execute(
        "SELECT COUNT(*) FROM vt_request_usage WHERE utc_day=?",
        (_utc_day(),),
    ).fetchone()
    return int(row[0])


def _next_job():
    """Select the oldest job in the highest-priority available queue."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_request_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_at REAL NOT NULL,
                utc_day TEXT NOT NULL
            )
        """)
        usage = _usage_today(conn)
        if usage >= MAX_PER_DAY:
            return None

        now = time.time()
        conn.execute(
            "DELETE FROM vt_dispatches WHERE dispatched_at <= ?",
            (now - 60,),
        )
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM vt_dispatches"
        ).fetchone()["n"]

        if recent >= MAX_PER_MINUTE:
            return None

        # Reserve the fourth slot for critical work when critical work is queued.
        # Non-critical work is capped at three requests per rolling minute.
        critical = conn.execute(
            "SELECT COUNT(*) AS n FROM vt_jobs WHERE status='pending' AND priority=0"
        ).fetchone()["n"]

        row = conn.execute(
            """SELECT * FROM vt_jobs
               WHERE status='pending'
               ORDER BY priority ASC, created_at ASC, id ASC
               LIMIT 1"""
        ).fetchone()

        if not row:
            return None

        # If a critical job is waiting, never spend the fourth slot on a
        # non-critical job.
        if recent >= MAX_PER_MINUTE - 1 and critical > 0:
            if int(row["priority"]) != 0:
                return None

        # When no critical work is queued, non-critical work may use slot four.
        conn.execute(
            "INSERT INTO vt_dispatches(dispatched_at) VALUES(?)", (now,)
        )
        conn.execute(
            "UPDATE vt_jobs SET status='processing', updated_at=? WHERE id=?",
            (now, row["id"]),
        )
        conn.commit()
        return dict(row)


def _save_result(job, result):
    now = time.time()
    with _connect() as conn:
        conn.execute(
            """UPDATE vt_jobs SET status='completed', result_json=?, updated_at=?
               WHERE id=?""",
            (json.dumps(result), now, job["id"]),
        )
        conn.commit()


def _worker_loop():
    global _cooldown_until

    while not _stop.is_set():
        job = None
        try:
            if time.time() < _cooldown_until:
                _stop.wait(min(1, _cooldown_until - time.time()))
                continue

            # Complete cached jobs without consuming dispatch slots.
            with _connect() as conn:
                pending_jobs = conn.execute(
                    """SELECT * FROM vt_jobs
                       WHERE status='pending'
                       ORDER BY priority ASC, created_at ASC, id ASC
                       LIMIT 100"""
                ).fetchall()

            cached_job = None
            cached_result = None
            for candidate in pending_jobs:
                candidate_result = get_cached_result(
                    candidate["kind"], candidate["indicator"]
                )
                if candidate_result is not None:
                    cached_job = dict(candidate)
                    cached_result = candidate_result
                    break

            if cached_job is not None:
                _save_result(cached_job, cached_result)
                continue

            job = _next_job()
            if not job:
                _stop.wait(POLL_SECONDS)
                continue

            if job["kind"] == "ip":
                result = lookup_ip(job["indicator"])
            else:
                result = lookup_file_hash(job["indicator"])

            if result.get("reason") == "rate_limited":
                # Respect the server's Retry-After value and leave the job pending.
                retry_after = result.get("retry_after_seconds", 60)
                try:
                    retry_after = max(1, min(int(retry_after), 86400))
                except (TypeError, ValueError):
                    retry_after = 60

                _cooldown_until = time.time() + retry_after
                with _connect() as conn:
                    conn.execute(
                        """UPDATE vt_jobs SET status='pending', updated_at=?
                           WHERE id=?""",
                        (time.time(), job["id"]),
                    )
                    conn.commit()
                continue

            if result.get("reason") in {
                "minute_rate_limit",
                "daily_quota_exceeded",
            }:
                # These are local limits, not completed VirusTotal lookups.
                with _connect() as conn:
                    conn.execute(
                        """UPDATE vt_jobs SET status='pending', updated_at=?
                           WHERE id=?""",
                        (time.time(), job["id"]),
                    )
                    conn.commit()
                _stop.wait(5)
                continue

            _save_result(job, result)

        except Exception:
            # Return an in-flight job to the queue after an unexpected error.
            if job is not None:
                try:
                    with _connect() as conn:
                        conn.execute(
                            """UPDATE vt_jobs SET status='pending', updated_at=?
                               WHERE id=? AND status='processing'""",
                            (time.time(), job["id"]),
                        )
                        conn.commit()
                except Exception:
                    pass
            _stop.wait(POLL_SECONDS)


def start_scheduler():
    global _thread
    initialize()
    if _thread and _thread.is_alive():
        return

    # Recover jobs left in processing after an interrupted run.
    with _connect() as conn:
        conn.execute(
            """UPDATE vt_jobs SET status='pending', updated_at=?
               WHERE status='processing'""",
            (time.time(),),
        )
        conn.commit()

    _stop.clear()
    _thread = threading.Thread(
        target=_worker_loop, name="aegistrace-vt-scheduler", daemon=True
    )
    _thread.start()


def stop_scheduler():
    _stop.set()
    thread = _thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=POLL_SECONDS + 2)
