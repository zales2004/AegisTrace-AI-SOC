
from datetime import datetime, timezone
from pathlib import Path
import re
import socket

AUTH_LOG = Path("/var/log/auth.log")
HOSTNAME = socket.gethostname()

# Match actual SSH authentication outcomes, not generic sshd messages.
FAILED_PASSWORD = re.compile(
    r"sshd(?:\[\d+\])?: Failed password for "
    r"(?:invalid user )?(?P<username>\S+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port \d+"
)

INVALID_USER = re.compile(
    r"sshd(?:\[\d+\])?: Invalid user "
    r"(?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)

ACCEPTED_LOGIN = re.compile(
    r"sshd(?:\[\d+\])?: Accepted "
    r"(?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<username>\S+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port \d+"
)

AUTH_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure;.*?"
    r"(?:rhost=(?P<ip>\S*))"
)


def classify_line(line):
    """Return a normalized event for recognized SSH auth outcomes."""
    match = FAILED_PASSWORD.search(line)
    if match:
        return {
            "event_type": "authentication_failure",
            "username": match.group("username"),
            "source_ip": match.group("ip"),
        }

    match = INVALID_USER.search(line)
    if match:
        return {
            "event_type": "invalid_user",
            "username": match.group("username"),
            "source_ip": match.group("ip"),
        }

    match = ACCEPTED_LOGIN.search(line)
    if match:
        return {
            "event_type": "authentication_success",
            "username": match.group("username"),
            "source_ip": match.group("ip"),
        }

    match = AUTH_FAILURE.search(line)
    if match:
        ip = match.group("ip")
        if ip and ip != "-":
            return {
                "event_type": "authentication_failure",
                "username": None,
                "source_ip": ip,
            }

    # Ignore generic SSH service and startup messages.
    return None


def collect_auth_events(limit=500):
    """Read recent authentication outcomes from /var/log/auth.log."""
    if limit < 1:
        raise ValueError("limit must be at least 1")

    if not AUTH_LOG.exists():
        raise FileNotFoundError(
            f"Authentication log not found: {AUTH_LOG}"
        )

    with AUTH_LOG.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        lines = file.readlines()[-limit:]

    events = []

    for line in lines:
        parsed = classify_line(line)
        if parsed is None:
            continue

        events.append({
            "host": HOSTNAME,
            **parsed,
            "raw_evidence": line.rstrip("\r\n"),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })

    return events


if __name__ == "__main__":
    try:
        events = collect_auth_events()
        print(f"Host: {HOSTNAME}")
        print(f"Recognized authentication events: {len(events)}")

        for event in events[-10:]:
            print(event)

    except PermissionError:
        print(
            "Permission denied. Run with sudo and the absolute "
            "path to the .aegis Python interpreter."
        )
    except FileNotFoundError as error:
        print(error)
