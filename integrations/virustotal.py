"""VirusTotal enrichment for AegisTrace. No file uploads; hash-only lookups."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import requests
from integrations.vt_limits import reserve_request
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
DB_PATH = Path(os.getenv("AEGISTRACE_DB_PATH", "data/aegistrace.db"))
BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = 8
CACHE_TTL_SECONDS = int(os.getenv("VT_CACHE_TTL_SECONDS", "21600"))


def _db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vt_cache (
            indicator_type TEXT NOT NULL,
            indicator TEXT NOT NULL,
            result_json TEXT NOT NULL,
            checked_at REAL NOT NULL,
            PRIMARY KEY (indicator_type, indicator)
        )
    """)
    conn.commit()
    return conn


def _cached(kind: str, indicator: str) -> dict[str, Any] | None:
    import json
    with _db() as conn:
        row = conn.execute(
            "SELECT result_json, checked_at FROM vt_cache WHERE indicator_type=? AND indicator=?",
            (kind, indicator),
        ).fetchone()
    if not row or time.time() - float(row["checked_at"]) > CACHE_TTL_SECONDS:
        return None
    try:
        result = json.loads(row["result_json"])
        result["cached"] = True
        return result
    except (ValueError, TypeError):
        return None



def get_cached_result(kind: str, indicator: str) -> dict[str, Any] | None:
    """Return a fresh cached report without making any network request."""
    if kind not in {"ip", "file"}:
        return None
    return _cached(kind, str(indicator).strip().lower())


def _store(kind: str, indicator: str, result: dict[str, Any]) -> None:
    import json
    with _db() as conn:
        conn.execute(
            """INSERT INTO vt_cache(indicator_type, indicator, result_json, checked_at)
               VALUES(?,?,?,?)
               ON CONFLICT(indicator_type, indicator) DO UPDATE SET
                 result_json=excluded.result_json, checked_at=excluded.checked_at""",
            (kind, indicator, json.dumps(result), time.time()),
        )
        conn.commit()


def _no_info(reason: str) -> dict[str, Any]:
    return {
        "available": False,
        "status": "no_info",
        "message": "No details available from VirusTotal",
        "reason": reason,
        "cached": False,
    }


def _request(kind: str, indicator: str) -> dict[str, Any]:
    if not API_KEY:
        return _no_info("api_key_not_configured")
    cached = _cached(kind, indicator)
    if cached is not None:
        return cached

    allowed, limit_reason = reserve_request()
    if not allowed:
        return _no_info(limit_reason or "request_limited")

    headers = {"x-apikey": API_KEY}
    endpoint = f"{BASE_URL}/ip_addresses/{indicator}" if kind == "ip" else f"{BASE_URL}/files/{indicator}"
    try:
        response = requests.get(endpoint, headers=headers, timeout=TIMEOUT)
        if response.status_code == 404:
            result = _no_info("no_report")
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "60")
            try:
                retry_after_seconds = max(1, min(int(float(retry_after)), 86400))
            except (TypeError, ValueError):
                retry_after_seconds = 60
            result = _no_info("rate_limited")
            result["retry_after_seconds"] = retry_after_seconds
        elif response.status_code in (401, 403):
            result = _no_info("api_key_or_permission_error")
        else:
            response.raise_for_status()
            payload = response.json().get("data", {})
            attrs = payload.get("attributes", {})
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            result = {
                "available": True,
                "status": "reported",
                "message": "VirusTotal report available",
                "indicator_type": kind,
                "indicator": indicator,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": int(stats.get("harmless", 0) or 0),
                "undetected": int(stats.get("undetected", 0) or 0),
                "reputation": attrs.get("reputation"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "permalink": f"https://www.virustotal.com/gui/{'ip-address' if kind == 'ip' else 'file'}/{indicator}",
                "cached": False,
            }
            if malicious > 0:
                result["status"] = "malicious"
            elif suspicious > 0:
                result["status"] = "suspicious"
            else:
                result["status"] = "no_detections"
                result["message"] = "No malicious detections reported by VirusTotal"
    except requests.RequestException:
        result = _no_info("service_unavailable")
    except (ValueError, TypeError):
        result = _no_info("invalid_response")

    # Cache successful reports and no-report/rate-limit responses only briefly for failures.
    if result.get("available"):
        _store(kind, indicator, result)
    return result


def lookup_ip(ip: str) -> dict[str, Any]:
    try:
        parsed = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return _no_info("invalid_ip")
    # Do not query private, loopback, link-local, reserved or documentation addresses.
    if not parsed.is_global:
        return _no_info("not_publicly_routable")
    return _request("ip", str(parsed))


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lookup_file_hash(sha256: str) -> dict[str, Any]:
    value = str(sha256).strip().lower()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        return _no_info("invalid_sha256")
    return _request("file", value)
