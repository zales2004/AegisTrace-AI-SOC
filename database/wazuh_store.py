import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from database.storage import DB_PATH, get_connection


def initialize_wazuh_store():
    """Create the Wazuh history table without changing existing records."""
    with get_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS wazuh_alerts (
                wazuh_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_level INTEGER NOT NULL DEFAULT 0,
                agent TEXT NOT NULL DEFAULT 'Unknown',
                agent_id TEXT NOT NULL DEFAULT '',
                source_ip TEXT,
                description TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL,
                ingested_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_wazuh_timestamp
            ON wazuh_alerts(timestamp)
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_wazuh_severity
            ON wazuh_alerts(severity)
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_wazuh_source_ip
            ON wazuh_alerts(source_ip)
        """)

        # Add workflow fields to existing databases without deleting alerts.
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(wazuh_alerts)")
        }
        if "status" not in columns:
            db.execute(
                "ALTER TABLE wazuh_alerts "
                "ADD COLUMN status TEXT NOT NULL DEFAULT 'open'"
            )
        if "closed_at" not in columns:
            db.execute(
                "ALTER TABLE wazuh_alerts ADD COLUMN closed_at TEXT"
            )


def save_wazuh_alert(alert):
    """Insert one Wazuh alert; return False when its ID already exists."""
    wazuh_id = str(alert.get("id") or "").strip()
    if not wazuh_id:
        raise ValueError("Wazuh alert is missing its stable event ID")

    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as db:
        cursor = db.execute("""
            INSERT OR IGNORE INTO wazuh_alerts (
                wazuh_id, timestamp, severity, rule_id, rule_level,
                agent, agent_id, source_ip, description, evidence,
                raw_json, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            wazuh_id,
            str(alert.get("timestamp") or now),
            str(alert.get("severity") or "low").lower(),
            str(alert.get("rule_id") or "Unknown"),
            int(alert.get("rule_level") or 0),
            str(alert.get("agent") or "Unknown"),
            str(alert.get("agent_id") or ""),
            alert.get("source_ip"),
            str(alert.get("description") or ""),
            str(alert.get("evidence") or ""),
            json.dumps(alert.get("raw_event", {}), ensure_ascii=False),
            now,
        ))
        return cursor.rowcount == 1


def ingest_wazuh_alerts(alerts):
    """Persist new Wazuh documents without re-ingesting known source events.

    Existing rows are preserved, including their analyst workflow statuses.
    Distinct Wazuh document IDs for an already stored source event are not
    inserted as additional history rows.
    """
    received = len(alerts)
    inserted = 0
    document_duplicates = 0
    source_event_duplicates = 0

    with get_connection() as db:
        known_document_ids = {
            row[0] for row in db.execute(
                "SELECT wazuh_id FROM wazuh_alerts"
            ).fetchall()
        }
        known_source_ids = {
            str(value).strip()
            for (value,) in db.execute(
                "SELECT json_extract(raw_json, '$.id') "
                "FROM wazuh_alerts "
                "WHERE json_extract(raw_json, '$.id') IS NOT NULL"
            ).fetchall()
            if str(value).strip()
        }

    batch_document_ids = set()
    batch_source_ids = set()

    for alert in alerts:
        document_id = str(alert.get("id") or "").strip()
        raw_event = alert.get("raw_event") or {}
        source_id = str(raw_event.get("id") or "").strip()

        if not document_id:
            continue

        if document_id in known_document_ids or document_id in batch_document_ids:
            document_duplicates += 1
            continue

        batch_document_ids.add(document_id)

        if source_id and (
            source_id in known_source_ids or source_id in batch_source_ids
        ):
            source_event_duplicates += 1
            continue

        if source_id:
            batch_source_ids.add(source_id)

        if save_wazuh_alert(alert):
            inserted += 1
            known_document_ids.add(document_id)
            if source_id:
                known_source_ids.add(source_id)

    return {
        "received": received,
        "inserted": inserted,
        "document_duplicates": document_duplicates,
        "source_event_duplicates": source_event_duplicates,
        "duplicates": document_duplicates + source_event_duplicates,
        "skipped_missing_document_id": received - inserted
            - document_duplicates - source_event_duplicates,
    }


def get_wazuh_alert_history(
    limit=100,
    offset=0,
    severity=None,
    search=None,
    period="10d",
    status="all",
):
    """Return paginated history with time-range and status filters."""
    from datetime import timedelta

    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))

    clauses = []
    params = []

    if severity and severity.lower() in {
        "low", "medium", "high", "critical"
    }:
        clauses.append("severity = ?")
        params.append(severity.lower())

    if status in {"open", "closed"}:
        clauses.append("status = ?")
        params.append(status)

    if period in {"24h", "3d", "10d"}:
        hours = {"24h": 24, "3d": 72, "10d": 240}[period]
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).isoformat()
        clauses.append("timestamp >= ?")
        params.append(cutoff)

    if search and search.strip():
        term = f"%{search.strip()}%"
        clauses.append("""
            (description LIKE ? OR source_ip LIKE ? OR agent LIKE ?
             OR rule_id LIKE ? OR evidence LIKE ?)
        """)
        params.extend([term] * 5)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    with get_connection() as db:
        total = db.execute(
            "SELECT COUNT(*) FROM wazuh_alerts" + where,
            params,
        ).fetchone()[0]

        rows = db.execute(
            "SELECT * FROM wazuh_alerts" + where
            + " ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "period": period,
        "status": status,
        "alerts": [dict(row) for row in rows],
    }






def get_wazuh_alert_status_counts():
    """Count every stored alert by workflow status."""
    with get_connection() as db:
        rows = db.execute("""
            SELECT status, COUNT(*) AS count
            FROM wazuh_alerts
            GROUP BY status
        """).fetchall()

    counts = {"open": 0, "closed": 0}
    for row in rows:
        if row["status"] in counts:
            counts[row["status"]] = row["count"]

    return {
        "open": counts["open"],
        "closed": counts["closed"],
        "total": counts["open"] + counts["closed"],
    }


def get_wazuh_alert_statuses(wazuh_ids):
    """Fetch saved statuses for specific alert IDs without a history limit."""
    ids = list(dict.fromkeys(str(value) for value in wazuh_ids if value))
    if not ids:
        return {}

    placeholders = ",".join("?" for _ in ids)
    with get_connection() as db:
        rows = db.execute(
            f"""
            SELECT wazuh_id, status, closed_at
            FROM wazuh_alerts
            WHERE wazuh_id IN ({placeholders})
            """,
            ids,
        ).fetchall()

    return {
        row["wazuh_id"]: {
            "status": row["status"],
            "closed_at": row["closed_at"],
        }
        for row in rows
    }


def set_wazuh_alert_status(wazuh_id, status):
    """Persist an alert's workflow status without altering its evidence."""
    if status not in {"open", "closed"}:
        raise ValueError("Status must be 'open' or 'closed'")

    now = datetime.now(timezone.utc).isoformat()
    closed_at = now if status == "closed" else None

    with get_connection() as db:
        cursor = db.execute(
            """
            UPDATE wazuh_alerts
            SET status = ?, closed_at = ?
            WHERE wazuh_id = ?
            """,
            (status, closed_at, wazuh_id),
        )
        return cursor.rowcount > 0
