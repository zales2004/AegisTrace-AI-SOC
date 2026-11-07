
import sys
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collectors.linux_auth import collect_auth_events
from database.storage import (
    initialize_database,
    save_event,
    save_alert,
)


def detect_ssh_attacks(events, threshold=5):
    """Detect repeated SSH failures and successful logins after failures."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    failures = defaultdict(list)
    alerts = []

    for event in events:
        event_type = event.get("event_type")
        source_ip = event.get("source_ip")
        evidence = event.get("raw_evidence", "")

        if not source_ip:
            continue

        if event_type in ("authentication_failure", "invalid_user"):
            failures[source_ip].append(evidence)

        elif event_type == "authentication_success":
            previous_failures = failures[source_ip]

            if previous_failures:
                alerts.append({
                    "alert_type": "success_after_failures",
                    "severity": "high",
                    "source_ip": source_ip,
                    "failure_count": len(previous_failures),
                    "evidence": previous_failures + [evidence],
                    "recommendation": (
                        "Investigate the login, verify the account owner, "
                        "and review subsequent privileged activity."
                    ),
                })
                failures[source_ip] = []

    for source_ip, evidence_list in failures.items():
        if len(evidence_list) >= threshold:
            alerts.append({
                "alert_type": "repeated_ssh_failures",
                "severity": "medium",
                "source_ip": source_ip,
                "failure_count": len(evidence_list),
                "evidence": evidence_list,
                "recommendation": (
                    "Review the source IP and authentication logs. "
                    "Consider a temporary block only after verification "
                    "and approval."
                ),
            })

    return alerts


def run_detection():
    initialize_database()
    events = collect_auth_events()

    saved_events = 0
    duplicate_events = 0

    for event in events:
        event_id = save_event(event)

        if event_id is not None:
            saved_events += 1
        else:
            duplicate_events += 1

    alerts = detect_ssh_attacks(events)

    saved_alerts = 0

    for alert in alerts:
        alert_id = save_alert(alert, host="ubuntusoc")
        if alert_id is not None:
            saved_alerts += 1

    print(f"Events collected: {len(events)}")
    print(f"New events saved: {saved_events}")
    print(f"Duplicate events skipped: {duplicate_events}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Alerts saved to database: {saved_alerts}")

    for alert in alerts:
        print(f"\nALERT: {alert['alert_type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failure count: {alert['failure_count']}")
        print(f"Recommendation: {alert['recommendation']}")


if __name__ == "__main__":
    run_detection()
