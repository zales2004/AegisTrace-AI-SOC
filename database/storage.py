import hashlib
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "aegistrace.db"


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")

        connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                host TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                timestamp TEXT NOT NULL,
                raw_evidence TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                source_ip TEXT,
                host TEXT,
                title TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                summary TEXT NOT NULL DEFAULT '',
                facts_json TEXT NOT NULL DEFAULT '[]',
                hypotheses_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER NOT NULL REFERENCES incidents(id),
                alert_id INTEGER NOT NULL REFERENCES alerts(id),
                PRIMARY KEY (incident_id, alert_id)
            );

            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER REFERENCES incidents(id),
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                approved_by TEXT,
                approved_at TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                verification_result TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_type
                ON events(event_type);

            CREATE INDEX IF NOT EXISTS idx_events_source_ip
                ON events(source_ip);

            CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status);

            CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);
         """)

def save_event(event):
    """Save an event once; return its ID, or None if it is a duplicate."""
    now = datetime.now(timezone.utc).isoformat()

    # Use stable log fields; collected_at changes on every collection run.
    fingerprint_fields = {
        "host": event.get("host", "unknown"),
        "event_type": event.get("event_type", "unknown"),
        "source_ip": event.get("source_ip"),
        "username": event.get("username"),
        "raw_evidence": event.get("raw_evidence", ""),
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_fields,
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    with get_connection() as connection:
        # Add the fingerprint column if this is an existing database.
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(events)")
        }
        if "fingerprint" not in columns:
            connection.execute("ALTER TABLE events ADD COLUMN fingerprint TEXT")

        # Backfill older records so they are not inserted again.
        rows = connection.execute(
            "SELECT id, event_json FROM events WHERE fingerprint IS NULL"
        ).fetchall()

        for row in rows:
            try:
                old_event = json.loads(row["event_json"])
            except (TypeError, json.JSONDecodeError):
                continue

            old_fields = {
                "host": old_event.get("host", "unknown"),
                "event_type": old_event.get("event_type", "unknown"),
                "source_ip": old_event.get("source_ip"),
                "username": old_event.get("username"),
                "raw_evidence": old_event.get("raw_evidence", ""),
            }
            old_fingerprint = hashlib.sha256(
                json.dumps(
                    old_fields,
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()

            connection.execute(
                "UPDATE events SET fingerprint = ? WHERE id = ?",
                (old_fingerprint, row["id"]),
            )

        existing = connection.execute(
            "SELECT id FROM events WHERE fingerprint = ? LIMIT 1",
            (fingerprint,),
        ).fetchone()

        if existing:
            return None

        cursor = connection.execute(
            """
            INSERT INTO events (
                event_type, host, source_ip, username, timestamp,
                raw_evidence, event_json, created_at, fingerprint
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(event.get("event_type", "unknown")),
                str(event.get("host", "unknown")),
                event.get("source_ip"),
                event.get("username"),
                str(event.get("timestamp") or now),
                str(event.get("raw_evidence", "")),
                json.dumps(event, ensure_ascii=False),
                now,
                fingerprint,
            ),
        )
        return cursor.lastrowid



def save_alert(alert, host="unknown"):
    """Persist an alert and return its database ID."""
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO alerts (
                alert_type, severity, source_ip, host, title,
                evidence_json, recommendation, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(alert.get("alert_type", "unknown")),
                str(alert.get("severity", "medium")).lower(),
                alert.get("source_ip"),
                host,
                str(alert.get("title") or alert.get("alert_type", "Security alert")),
                json.dumps(alert.get("evidence", []), ensure_ascii=False),
                str(alert.get("recommendation", "Investigate the evidence.")),
                now,
            ),
        )
        return cursor.lastrowid


def get_recent_events(limit=100):
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_recent_alerts(limit=100):
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized: {DB_PATH}")
