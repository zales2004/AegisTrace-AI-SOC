"""Polling file monitor: hashes new/changed files and looks up hashes in VirusTotal."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from integrations.virustotal import DB_PATH, sha256_file
from integrations.vt_scheduler import enqueue, get_result

MONITOR_DIRS = [Path(p).expanduser().resolve() for p in os.getenv("AEGISTRACE_MONITOR_DIRS", "").split(os.pathsep) if p.strip()]
POLL_SECONDS = max(5, int(os.getenv("AEGISTRACE_FILE_POLL_SECONDS", "15")))
MAX_FILE_BYTES = max(1, int(os.getenv("AEGISTRACE_MAX_FILE_MB", "100"))) * 1024 * 1024
_stop = threading.Event()
_thread: threading.Thread | None = None


def _init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    import sqlite3
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_observations (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mtime REAL NOT NULL,
                sha256 TEXT NOT NULL,
                vt_json TEXT NOT NULL,
                observed_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_event_history (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL, size INTEGER NOT NULL, mtime REAL NOT NULL,
                sha256 TEXT NOT NULL, vt_json TEXT NOT NULL,
                observed_at REAL NOT NULL, completed_at REAL
            )
        """)
        conn.commit()


def scan_once() -> dict:
    _init_db()
    scanned = 0
    skipped = 0
    errors = 0
    import sqlite3
    for root in MONITOR_DIRS:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            try:
                if not path.is_file() or path.is_symlink():
                    continue
                stat = path.stat()
                if stat.st_size > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    old = conn.execute("SELECT size, mtime FROM file_observations WHERE path=?", (str(path),)).fetchone()
                if old and int(old[0]) == stat.st_size and float(old[1]) == stat.st_mtime:
                    # Repair/backfill history if an observation exists without an event.
                    with sqlite3.connect(DB_PATH, timeout=10) as conn:
                        conn.execute("""
                            INSERT INTO file_event_history
                                (path,size,mtime,sha256,vt_json,observed_at,completed_at)
                            SELECT o.path,o.size,o.mtime,o.sha256,o.vt_json,o.observed_at,NULL
                            FROM file_observations AS o
                            WHERE o.path=?
                              AND NOT EXISTS (
                                  SELECT 1 FROM file_event_history AS h
                                  WHERE h.path=o.path AND h.sha256=o.sha256
                              )
                        """, (str(path),))
                        conn.commit()
                    continue
                digest = sha256_file(path)
                enqueue("file", digest, "file")
                vt = get_result("file", digest)
                if vt.get("status") in {"pending", "processing", "not_queued"}:
                    vt = {
                        "available": False,
                        "status": vt.get("status", "pending"),
                        "message": "File hash queued for VirusTotal lookup."
                    }
                else:
                    vt = vt.get("result") or vt
                observed_now = time.time()
                completed_now = observed_now if vt.get("status") not in {"pending", "processing", "not_queued"} else None
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.execute("""
                        INSERT INTO file_observations(path,size,mtime,sha256,vt_json,observed_at)
                        VALUES(?,?,?,?,?,?)
                        ON CONFLICT(path) DO UPDATE SET
                          size=excluded.size, mtime=excluded.mtime, sha256=excluded.sha256,
                          vt_json=excluded.vt_json, observed_at=excluded.observed_at
                    """, (str(path), stat.st_size, stat.st_mtime, digest, json.dumps(vt), observed_now))
                    conn.execute("""
                        INSERT INTO file_event_history(path,size,mtime,sha256,vt_json,observed_at,completed_at)
                        VALUES(?,?,?,?,?,?,?)
                    """, (str(path), stat.st_size, stat.st_mtime, digest, json.dumps(vt), observed_now, completed_now))
                    conn.commit()
                scanned += 1
            except (OSError, PermissionError):
                errors += 1
    return {"updated": scanned, "skipped_large": skipped, "errors": errors, "directories": [str(p) for p in MONITOR_DIRS]}


def recent_files(limit: int = 100) -> list[dict]:
    _init_db()
    import sqlite3
    limit = max(1, min(int(limit), 500))
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT path,size,mtime,sha256,vt_json,observed_at FROM file_observations ORDER BY observed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            item["virustotal"] = json.loads(item.pop("vt_json"))
        except (ValueError, TypeError):
            item["virustotal"] = {
                "available": False,
                "message": "No details available from VirusTotal"
            }
            item.pop("vt_json", None)

        # Refresh the displayed result from the shared queue.
        try:
            queued = get_result("file", item["sha256"])
            if queued.get("status") == "completed":
                report = queued.get("result") or item["virustotal"]
                item["virustotal"] = report
                report_json = json.dumps(report)
                completed_at = queued.get("updated_at") or time.time()
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.execute(
                        "UPDATE file_observations SET vt_json=? WHERE path=? AND sha256=?",
                        (report_json, item["path"], item["sha256"]),
                    )
                    # Ensure there is a history row even if an older scan missed it.
                    conn.execute("""
                        INSERT INTO file_event_history
                            (path,size,mtime,sha256,vt_json,observed_at,completed_at)
                        SELECT o.path,o.size,o.mtime,o.sha256,o.vt_json,o.observed_at,?
                        FROM file_observations AS o
                        WHERE o.path=? AND o.sha256=?
                          AND NOT EXISTS (
                              SELECT 1 FROM file_event_history AS h
                              WHERE h.path=o.path AND h.sha256=o.sha256
                          )
                    """, (completed_at, item["path"], item["sha256"]))
                    conn.execute("""
                        UPDATE file_event_history
                        SET vt_json=?, completed_at=COALESCE(completed_at, ?)
                        WHERE path=? AND sha256=?
                    """, (report_json, completed_at, item["path"], item["sha256"]))
                    conn.commit()
            elif queued.get("status") in {"pending", "processing"}:
                item["virustotal"] = {
                    "available": False,
                    "status": queued["status"],
                    "message": "File hash queued for VirusTotal lookup."
                }
        except Exception:
            pass

        output.append(item)
    return output


def file_history(limit: int = 200) -> list[dict]:
    _init_db()
    import sqlite3
    limit = max(1, min(int(limit), 500))
    # Backfill any observation that does not yet have a matching history event.
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("""
            INSERT INTO file_event_history
                (path,size,mtime,sha256,vt_json,observed_at,completed_at)
            SELECT o.path,o.size,o.mtime,o.sha256,o.vt_json,o.observed_at,NULL
            FROM file_observations AS o
            WHERE NOT EXISTS (
                SELECT 1 FROM file_event_history AS h
                WHERE h.path=o.path AND h.sha256=o.sha256
            )
        """)
        conn.commit()
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT event_id,path,size,mtime,sha256,vt_json,observed_at,completed_at FROM file_event_history ORDER BY event_id DESC LIMIT ?", (limit,)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try: report = json.loads(item.pop("vt_json"))
        except (ValueError, TypeError): report = {"available": False, "status": "error", "message": "Could not parse stored result."}
        try:
            queued = get_result("file", item["sha256"])
            if queued.get("status") == "completed":
                report = queued.get("result") or report
                done = item.get("completed_at") or time.time()
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.execute("UPDATE file_event_history SET vt_json=?,completed_at=? WHERE event_id=?", (json.dumps(report), done, item["event_id"]))
                    conn.commit()
                item["completed_at"] = done
            elif queued.get("status") in {"pending", "processing", "not_queued"}:
                report = {"available": False, "status": queued.get("status", "pending"), "message": "File hash queued for VirusTotal lookup."}
        except Exception: pass
        item["virustotal"] = report
        result.append(item)
    return result


def start_file_monitor():
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    def loop():
        while not _stop.is_set():
            try:
                scan_once()
            except Exception:
                # Never crash the FastAPI app because a monitored file is unreadable.
                pass
            _stop.wait(POLL_SECONDS)
    _thread = threading.Thread(target=loop, name="aegistrace-file-monitor", daemon=True)
    _thread.start()


def stop_file_monitor():
    _stop.set()
    thread = _thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=POLL_SECONDS + 2)
