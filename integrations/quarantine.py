"""Audited, reversible quarantine for files in configured AegisTrace monitor roots."""
from __future__ import annotations
import hashlib, json, os, shutil, sqlite3, time
from pathlib import Path
from integrations.virustotal import DB_PATH, sha256_file
from integrations.file_monitor import MONITOR_DIRS

# Project-local quarantine. Owner-only permissions; for root-only isolation, run the
# service under a dedicated account and set AEGISTRACE_QUARANTINE_DIR accordingly.
QUARANTINE_DIR = Path(os.getenv("AEGISTRACE_QUARANTINE_DIR", str(DB_PATH.parent / "quarantine"))).expanduser().resolve()
AUTO_MIN_ENGINES = int(os.getenv("AEGISTRACE_AUTO_QUARANTINE_MIN_ENGINES", "100"))
AUTO_MALICIOUS_RATIO = float(os.getenv("AEGISTRACE_AUTO_QUARANTINE_RATIO", "0.90"))


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS quarantine_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT NOT NULL,
      quarantine_path TEXT, sha256 TEXT NOT NULL, verdict TEXT NOT NULL,
      malicious INTEGER NOT NULL, suspicious INTEGER NOT NULL, engine_total INTEGER NOT NULL,
      action TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL,
      created_at REAL NOT NULL, detail TEXT NOT NULL DEFAULT '')""")
    conn.commit()
    return conn


def _inside_monitored_root(path: Path) -> bool:
    for root in MONITOR_DIRS:
        try:
            path.relative_to(root)
            if path != root:
                return True
        except ValueError:
            continue
    return False


def _stats(report: dict) -> tuple[int, int, int, int]:
    malicious = int(report.get('malicious') or 0)
    suspicious = int(report.get('suspicious') or 0)
    harmless = int(report.get('harmless') or 0)
    undetected = int(report.get('undetected') or 0)
    return malicious, suspicious, harmless, undetected


def auto_eligible(report: dict) -> bool:
    if not isinstance(report, dict) or not report.get('available'):
        return False
    malicious, suspicious, harmless, undetected = _stats(report)
    total = malicious + suspicious + harmless + undetected
    return total >= AUTO_MIN_ENGINES and total > 0 and malicious / total >= AUTO_MALICIOUS_RATIO


def _audit(original, dest, digest, report, action, actor, reason, detail=''):
    malicious, suspicious, harmless, undetected = _stats(report)
    with _connect() as conn:
        conn.execute("""INSERT INTO quarantine_audit
          (original_path,quarantine_path,sha256,verdict,malicious,suspicious,engine_total,action,actor,reason,created_at,detail)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (str(original), str(dest) if dest else None, digest, str(report.get('status','unknown')),
           malicious, suspicious, malicious+suspicious+harmless+undetected, action, actor, reason, time.time(), detail))
        conn.commit()


def quarantine_file(path_text: str, expected_sha256: str, report: dict, actor: str = 'analyst', reason: str = 'Manual analyst action') -> dict:
    path = Path(path_text).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError('File is missing or is a symbolic link; quarantine refused.')
    resolved = path.resolve(strict=True)
    if not _inside_monitored_root(resolved):
        raise ValueError('Only files inside configured monitored directories can be quarantined.')
    expected = str(expected_sha256).strip().lower()
    if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
        raise ValueError('Invalid SHA-256 value.')
    actual = sha256_file(resolved)
    if actual != expected:
        raise ValueError('File changed since scanning; hash mismatch. Scan it again before quarantining.')
    # Refuse to quarantine if another observation no longer matches the requested file/hash.
    with _connect() as conn:
        row = conn.execute('SELECT sha256 FROM file_observations WHERE path=?', (str(resolved),)).fetchone()
        if not row or row['sha256'] != expected:
            raise ValueError('File is not a current recorded observation for this hash.')
        prior = conn.execute("SELECT quarantine_path FROM quarantine_audit WHERE sha256=? AND action IN ('manual_quarantined','auto_quarantined') ORDER BY id DESC LIMIT 1", (expected,)).fetchone()
    if prior:
        return {'status':'already_quarantined','quarantine_path':prior['quarantine_path'],'sha256':expected}
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try: os.chmod(QUARANTINE_DIR, 0o700)
    except OSError: pass
    # Avoid collisions; the hash prefix plus a timestamp makes destination unique.
    dest = QUARANTINE_DIR / f'{expected}_{int(time.time())}_{resolved.name}'
    try:
        shutil.move(str(resolved), str(dest))
        os.chmod(dest, 0o600)
        moved_hash = sha256_file(dest)
        if moved_hash != expected:
            # Do not report success if post-move verification fails.
            _audit(resolved, dest, expected, report, 'verification_failed', actor, reason, 'Hash changed after move; manual recovery required.')
            raise RuntimeError('Post-move hash verification failed; inspect quarantine immediately.')
        _audit(resolved, dest, expected, report, 'auto_quarantined' if actor == 'automatic' else 'manual_quarantined', actor, reason)
    except Exception as exc:
        if not isinstance(exc, RuntimeError):
            _audit(resolved, None, expected, report, 'quarantine_failed', actor, reason, type(exc).__name__)
        raise
    return {'status':'quarantined','original_path':str(resolved),'quarantine_path':str(dest),'sha256':expected}


def process_auto_quarantine(files: list[dict]) -> list[dict]:
    """Quarantine only fully reported high-confidence results; annotate outcomes."""
    for item in files:
        report = item.get('virustotal') or {}
        # Persist the displayed quarantine state across refreshes, even though the
        # original path no longer exists after a successful move.
        with _connect() as conn:
            prior = conn.execute("SELECT quarantine_path, action FROM quarantine_audit WHERE sha256=? AND action IN ('manual_quarantined','auto_quarantined') ORDER BY id DESC LIMIT 1", (item.get('sha256',''),)).fetchone()
        if prior:
            item['quarantine_status'] = 'quarantined'
            item['quarantine_path'] = prior['quarantine_path']
            continue
        if not auto_eligible(report) or item.get('quarantine_status') in {'quarantined','already_quarantined'}:
            continue
        try:
            result = quarantine_file(item['path'], item['sha256'], report, actor='automatic', reason='VirusTotal threshold met')
            item['quarantine_status'] = result['status']
            item['quarantine_path'] = result.get('quarantine_path')
            item['path'] = item['path']  # preserve original path in this response
        except Exception as exc:
            item['quarantine_status'] = 'failed'
            item['quarantine_error'] = str(exc)
    return files


def audit_recent(limit: int = 100) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute('SELECT * FROM quarantine_audit ORDER BY id DESC LIMIT ?', (max(1,min(int(limit),500)),)).fetchall()
    return [dict(row) for row in rows]
