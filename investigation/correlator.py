"""Conservative, evidence-linked correlation for stored Wazuh alerts."""

import json
import re
import sqlite3
from datetime import datetime, timezone
from itertools import combinations

from database.storage import DB_PATH


WINDOW_SECONDS = 300
MAX_CHAIN_SECONDS = 600
MAX_ALERTS = 500
MAX_TEXT_LENGTH = 500
MAX_ARGUMENT_LENGTH = 200

PLACEHOLDERS = {
    "", "not recorded", "unknown", "none", "null", "n/a", "-"
}

TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
AUDIT_TOKEN_PATTERN = re.compile(
    r"""([A-Za-z0-9_.-]+)=("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s]+)"""
)
AUDIT_TYPE_PATTERN = re.compile(r"\btype=([A-Z0-9_]+)")
SYSLOG_PID_PATTERN = re.compile(r"\b(?:sudo|sshd|su)\[(\d+)\]:")

SENSITIVE_ARGUMENT_PATTERN = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key)"
)


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp into Unix epoch seconds."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, TypeError):
        return None


def valid_entity(value):
    """Normalize missing or placeholder entity values to None."""
    if value is None:
        return None

    value = str(value).strip()
    return None if value.lower() in PLACEHOLDERS else value


def as_dict(value):
    return value if isinstance(value, dict) else {}


def first_value(*values):
    """Return the first non-placeholder value."""
    for value in values:
        if isinstance(value, list):
            value = value[0] if value else None

        result = valid_entity(value)
        if result:
            return result

    return None


def parse_json_object(value):
    """Parse a JSON object held in a string."""
    if isinstance(value, dict):
        return value

    if not isinstance(value, str):
        return {}

    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


def parse_audit_fields(full_log):
    """Extract auditd key/value fields and event types from a log."""
    fields = {}

    for key, value in AUDIT_TOKEN_PATTERN.findall(full_log or ""):
        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]

        fields[key] = value

    event_types = sorted(set(AUDIT_TYPE_PATTERN.findall(full_log or "")))
    return fields, event_types


def redact_argument(value):
    """Redact obvious credential-bearing command arguments."""
    value = str(value)[:MAX_ARGUMENT_LENGTH]

    if SENSITIVE_ARGUMENT_PATTERN.search(value):
        if "=" in value:
            key = value.split("=", 1)[0]
            return f"{key}=[REDACTED]"
        return "[REDACTED]"

    return value


def extract_command(audit_fields):
    """Build a bounded command description from auditd EXECVE arguments."""
    executable = first_value(
        audit_fields.get("exe"),
        audit_fields.get("comm"),
    )

    argument_items = []

    for key, value in audit_fields.items():
        match = re.fullmatch(r"a(\d+)", key)
        if match:
            argument_items.append(
                (int(match.group(1)), redact_argument(value))
            )

    arguments = [
        value
        for _, value in sorted(argument_items, key=lambda item: item[0])
    ]

    parts = []
    if executable:
        parts.append(executable)
    parts.extend(arguments)

    if not parts:
        return None

    return " ".join(parts)[:MAX_TEXT_LENGTH]


def extract_dns_details(full_log, data):
    """Extract structured DNS telemetry from a JSON full_log payload."""
    payload = parse_json_object(full_log)

    if not payload and isinstance(data.get("dns"), dict):
        payload = data["dns"]

    event_type = first_value(
        payload.get("event_type"),
        data.get("event_type"),
    )

    if event_type not in {"dns_query", "dns_response"}:
        return {}

    questions = payload.get("questions") or []
    answers = payload.get("answers") or []

    if not isinstance(questions, list):
        questions = []
    if not isinstance(answers, list):
        answers = []

    first_question = as_dict(questions[0]) if questions else {}
    first_answer = as_dict(answers[0]) if answers else {}

    domain = first_value(
        first_question.get("domain"),
        payload.get("domain"),
        data.get("domain"),
        first_answer.get("domain"),
    )

    query_type = first_value(
        first_question.get("query_type"),
        payload.get("query_type"),
        data.get("query_type"),
    )

    normalized_answers = []

    for answer in answers[:20]:
        answer = as_dict(answer)
        normalized_answers.append({
            "domain": valid_entity(answer.get("domain")),
            "record_type": valid_entity(answer.get("record_type")),
            "value": valid_entity(answer.get("value")),
        })

    return {
        "event_type": event_type,
        "sensor": valid_entity(payload.get("sensor")),
        "interface": valid_entity(payload.get("interface")),
        "transaction_id": valid_entity(payload.get("transaction_id")),
        "dns_domain": domain,
        "dns_query_type": query_type,
        "dns_answers": normalized_answers,
        "response_code": payload.get("response_code"),
        "response_code_name": valid_entity(
            payload.get("response_code_name")
        ),
        "dns_source_ip": valid_entity(payload.get("source_ip")),
        "dns_destination_ip": valid_entity(payload.get("destination_ip")),
    }


def extract_details(row):
    """Extract normalized evidence from a stored Wazuh alert."""
    raw = parse_json_object(row["raw_json"])

    data = as_dict(raw.get("data"))
    agent_data = as_dict(raw.get("agent"))
    rule = as_dict(raw.get("rule"))
    mitre = as_dict(rule.get("mitre"))

    description = str(row["description"] or "")
    full_log = str(raw.get("full_log") or row["evidence"] or "")

    combined_text = f"{description} {full_log}".lower()

    audit_fields, audit_event_types = parse_audit_fields(full_log)
    dns_details = extract_dns_details(full_log, data)

    # Prefer auditd PID, then fall back to syslog-style PID.
    process_id = first_value(audit_fields.get("pid"))

    if not process_id:
        process_match = SYSLOG_PID_PATTERN.search(full_log)
        process_id = process_match.group(1) if process_match else None

    parent_process_id = first_value(audit_fields.get("ppid"))
    executable = first_value(audit_fields.get("exe"))

    process_name = first_value(
        audit_fields.get("comm"),
        data.get("process_name"),
    )

    syscall = first_value(audit_fields.get("syscall"))
    command = extract_command(audit_fields)

    username = first_value(
        data.get("dstuser"),
        data.get("srcuser"),
        data.get("username"),
        data.get("user"),
        data.get("uid"),
        audit_fields.get("acct"),
        audit_fields.get("uid"),
    )

    technique_ids = mitre.get("id", [])

    if isinstance(technique_ids, str):
        technique_ids = [technique_ids]

    if not isinstance(technique_ids, list):
        technique_ids = []

    technique_ids = sorted({
        value
        for value in technique_ids
        if isinstance(value, str)
        and TECHNIQUE_PATTERN.fullmatch(value)
    })

    agent = first_value(
        row["agent"],
        agent_data.get("name"),
    )

    source_ip = first_value(
        dns_details.get("dns_source_ip"),
        row["source_ip"],
        data.get("srcip"),
        data.get("src_ip"),
    )

    destination_ip = first_value(
        dns_details.get("dns_destination_ip"),
        data.get("dstip"),
        data.get("dst_ip"),
    )

    return {
        "wazuh_id": row["wazuh_id"],
        "source_event_id": valid_entity(raw.get("id")),
        "source_document_ids": [row["wazuh_id"]],
        "timestamp": row["timestamp"],
        "epoch": parse_timestamp(row["timestamp"]),
        "severity": row["severity"],
        "rule_id": row["rule_id"],
        "rule_level": row["rule_level"],
        "agent": agent,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "process_id": process_id,
        "parent_process_id": parent_process_id,
        "executable": executable,
        "process_name": process_name,
        "syscall": syscall,
        "command": command,
        "audit_event_types": audit_event_types,
        "audit_uid": valid_entity(audit_fields.get("uid")),
        "effective_uid": valid_entity(audit_fields.get("euid")),
        "login_uid": valid_entity(audit_fields.get("auid")),
        "audit_session": valid_entity(audit_fields.get("ses")),
        **dns_details,
        "description": description,
        "technique_ids": technique_ids,
        "text": combined_text,
    }


def linked_by_dns_transaction(a, b):
    """
    Link a DNS query to its response using transaction evidence.

    Requires the same host, transaction ID, domain and query type.
    When both endpoint pairs exist, they must be reversed.
    """
    if not a.get("epoch") or not b.get("epoch"):
        return None

    if abs(a["epoch"] - b["epoch"]) > WINDOW_SECONDS:
        return None

    if not a.get("agent") or a["agent"] != b.get("agent"):
        return None

    if {a.get("event_type"), b.get("event_type")} != {
        "dns_query", "dns_response"
    }:
        return None

    if not a.get("transaction_id"):
        return None

    if a.get("transaction_id") != b.get("transaction_id"):
        return None

    if not a.get("dns_domain") or (
        a.get("dns_domain") != b.get("dns_domain")
    ):
        return None

    if not a.get("dns_query_type") or (
        a.get("dns_query_type") != b.get("dns_query_type")
    ):
        return None

    query = a if a.get("event_type") == "dns_query" else b
    response = b if query is a else a

    query_source = query.get("dns_source_ip")
    query_destination = query.get("dns_destination_ip")
    response_source = response.get("dns_source_ip")
    response_destination = response.get("dns_destination_ip")

    endpoints_available = all((
        query_source,
        query_destination,
        response_source,
        response_destination,
    ))

    if endpoints_available:
        if (
            query_source != response_destination
            or query_destination != response_source
        ):
            return None

    return (
        "matching DNS query and response transaction "
        "(transaction ID, domain, query type and host)"
    )



def linked_by_evidence(a, b):
    """Return a defensible relationship between two events on the same host."""
    if a.get("epoch") is None or b.get("epoch") is None:
        return None

    if abs(a["epoch"] - b["epoch"]) > WINDOW_SECONDS:
        return None

    if not a.get("agent") or a["agent"] != b.get("agent"):
        return None

    dns_reason = linked_by_dns_transaction(a, b)
    if dns_reason:
        return dns_reason

    ar = str(a.get("rule_id") or "")
    br = str(b.get("rule_id") or "")

    ssh_failures = {"5710", "5712", "5760"}
    ssh_successes = {"5715"}
    pam_session_rules = {"5501", "5502"}

    a_failure = ar in ssh_failures
    b_failure = br in ssh_failures
    a_success = ar in ssh_successes
    b_success = br in ssh_successes

    a_pam_session = ar in pam_session_rules
    b_pam_session = br in pam_session_rules

    a_pid = a.get("process_id")
    b_pid = b.get("process_id")
    same_pid = bool(
        a_pid is not None
        and str(a_pid).strip()
        and b_pid is not None
        and str(a_pid) == str(b_pid)
    )

    same_user = bool(
        a.get("username")
        and a.get("username") == b.get("username")
    )
    same_source = bool(
        a.get("source_ip")
        and a.get("source_ip") == b.get("source_ip")
    )
    same_session = bool(
        a.get("audit_session") is not None
        and str(a.get("audit_session")) == str(b.get("audit_session"))
    )

    # SSH failures and success require account AND source identity.
    if (
        same_user and same_source
        and (
            (a_failure and (b_failure or b_success))
            or (b_failure and a_success)
        )
    ):
        if a_success or b_success:
            return (
                "SSH authentication failures and success for same "
                "account and source IP"
            )
        return (
            "repeated SSH authentication failures for same "
            "account and source IP"
        )

    # Successful SSH authentication may precede a PAM session event.
    if same_user and (
        (a_success and b_pam_session)
        or (b_success and a_pam_session)
    ):
        return "SSH authentication and PAM session for same account"

    # Successful sudo (5402) and its PAM session events must share
    # the exact process ID. Same username alone is not sufficient.
    a_sudo_success = ar == "5402"
    b_sudo_success = br == "5402"

    if (
        (a_sudo_success and b_pam_session)
        or (b_sudo_success and a_pam_session)
    ) and same_pid:
        return "sudo and PAM session events share the exact process ID"

    # PAM open/close events require an audit session or exact process ID.
    # Rule 5503 (PAM authentication failure) is deliberately excluded.
    if (
        a_pam_session and b_pam_session
        and (same_session or same_pid)
    ):
        return "PAM session events share an audit session or process ID"

    # Exact process relationship.
    if same_pid:
        return "same process ID on same agent within time window"

    a_ppid = a.get("parent_process_id")
    b_ppid = b.get("parent_process_id")

    # Parent-child process relationship.
    if (
        (a_pid is not None and b_ppid is not None
         and str(a_pid) == str(b_ppid))
        or
        (b_pid is not None and a_ppid is not None
         and str(b_pid) == str(a_ppid))
    ):
        return "parent-child process ID relationship on same agent"

    # Deliberately do not link on source IP, username, or host alone.
    return None

def deduplicate_source_events(alerts):
    """Collapse duplicate source events while preserving Wazuh document IDs."""
    unique = []
    by_source_id = {}

    for alert in alerts:
        source_id = alert.get("source_event_id")

        # Without a source event ID, do not guess whether records are duplicates.
        if not source_id:
            unique.append(alert)
            continue

        existing = by_source_id.get(source_id)

        if existing is None:
            alert["source_document_ids"] = list(dict.fromkeys(
                alert.get("source_document_ids", [alert["wazuh_id"]])
            ))
            by_source_id[source_id] = alert
            unique.append(alert)
            continue

        existing_ids = existing.setdefault("source_document_ids", [])

        for document_id in alert.get(
            "source_document_ids", [alert["wazuh_id"]]
        ):
            if document_id not in existing_ids:
                existing_ids.append(document_id)

    return unique


def evidence_projection(member):
    """Return bounded, structured evidence for candidate output."""
    optional_fields = (
        "event_type",
        "sensor",
        "interface",
        "transaction_id",
        "dns_domain",
        "dns_query_type",
        "dns_answers",
        "response_code",
        "response_code_name",
        "destination_ip",
        "parent_process_id",
        "executable",
        "process_name",
        "syscall",
        "command",
        "audit_event_types",
        "audit_uid",
        "effective_uid",
        "login_uid",
        "audit_session",
    )

    evidence = {
        "wazuh_id": member["wazuh_id"],
        "source_event_id": member.get("source_event_id"),
        "source_document_ids": member.get(
            "source_document_ids", [member["wazuh_id"]]
        ),
        "timestamp": member["timestamp"],
        "severity": member["severity"],
        "rule_id": member["rule_id"],
        "agent": member["agent"],
        "source_ip": member["source_ip"],
        "username": member["username"],
        "process_id": member["process_id"],
        "description": str(member["description"] or "")[:MAX_TEXT_LENGTH],
        "technique_ids": member["technique_ids"],
    }

    for field in optional_fields:
        value = member.get(field)
        if value is not None and value != []:
            evidence[field] = value

    return evidence


def classify_candidate(members, reasons):
    """Classify a chain conservatively using its observed event types."""
    rules = {str(member.get("rule_id") or "") for member in members}

    has_ssh_failure = bool(rules & {"5710", "5712", "5760"})
    has_pam_failure = "5503" in rules
    has_ssh_success = "5715" in rules
    has_pam_open = "5501" in rules

    has_dns_pair = any(
        "matching DNS query and response transaction" in reason
        for reason in reasons
    )

    has_exact_sudo_pam_link = any(
        "sudo and PAM session events share the exact process ID" in reason
        for reason in reasons
    )

    # SSH failures followed by a success deserve investigation.
    if has_ssh_failure and has_ssh_success:
        return (
            "suspicious_pattern",
            "SSH authentication failures were followed by a successful "
            "authentication. Verify whether the successful login was expected."
        )

    # SSH failures without a corresponding success.
    if has_ssh_failure:
        return (
            "suspicious_pattern",
            "Failed SSH authentication activity was observed. "
            "Review the source, account and frequency of attempts."
        )

    # PAM failures are not successful sessions.
    if has_pam_failure:
        return (
            "suspicious_pattern",
            "A PAM authentication failure was observed. Determine whether "
            "it relates to sudo, su or another PAM service."
        )

    # A sudo/PAM chain is routine only with exact process evidence.
    if (
        has_exact_sudo_pam_link
        and "5402" in rules
        and bool(rules & {"5501", "5502"})
        and rules <= {"5402", "5501", "5502"}
    ):
        return (
            "routine_activity",
            "A successful sudo event and its PAM session event(s) share "
            "the same process ID. Review the command and target account "
            "to confirm that the activity was expected."
        )

    # Routine SSH authentication/session sequence.
    if (
        has_ssh_success
        and has_pam_open
        and rules <= {"5715", "5501", "5502"}
    ):
        return (
            "routine_activity",
            "Successful SSH authentication was followed by a PAM session "
            "event. No failed authentication is present in this chain."
        )

    # A DNS pair is routine only when no other rule types are mixed in.
    if has_dns_pair and rules <= {"100200", "100201"}:
        return (
            "routine_activity",
            "A matching DNS query and response transaction was observed. "
            "The transaction alone does not establish malicious activity."
        )

    return (
        "inconclusive",
        "Related events were correlated, but the available evidence does "
        "not establish whether the activity is routine or suspicious."
    )



def correlate_alerts(alerts):
    """
    Build deterministic, time-bounded event components from evidence edges.

    Each event belongs to at most one candidate. Components cannot exceed
    MAX_CHAIN_SECONDS, even when a series of pairwise links is transitive.
    """
    alerts = sorted(
        alerts,
        key=lambda item: (
            item.get("epoch") or 0,
            str(item.get("wazuh_id") or "")
        )
    )

    # Ignore events without usable timestamps or document IDs.
    alerts = [
        item for item in alerts
        if item.get("epoch") is not None and item.get("wazuh_id")
    ]

    count = len(alerts)
    parent = list(range(count))
    component_start = [item["epoch"] for item in alerts]
    component_end = [item["epoch"] for item in alerts]
    edges = []

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    # Build pairwise evidence edges. Sorted input permits an early time cutoff.
    for i in range(count):
        for j in range(i + 1, count):
            delta = alerts[j]["epoch"] - alerts[i]["epoch"]
            if delta > WINDOW_SECONDS:
                break

            reason = linked_by_evidence(alerts[i], alerts[j])
            if reason:
                edges.append((i, j, reason))

    # Strong, specific links are considered before weaker contextual links.
    def edge_priority(edge):
        reason = edge[2].lower()
        if "dns transaction" in reason:
            return 0
        if "parent-child" in reason or "same process id" in reason:
            return 1
        if "audit identity" in reason or "pam session" in reason:
            return 2
        if "ssh authentication" in reason:
            return 3
        return 4

    edges.sort(key=lambda edge: (edge_priority(edge), edge[0], edge[1]))

    accepted_edges = []

    for i, j, reason in edges:
        left = find(i)
        right = find(j)

        if left == right:
            accepted_edges.append((i, j, reason))
            continue

        new_start = min(component_start[left], component_start[right])
        new_end = max(component_end[left], component_end[right])

        if new_end - new_start > MAX_CHAIN_SECONDS:
            continue

        # Deterministic union.
        root, child = (left, right) if left < right else (right, left)
        parent[child] = root
        component_start[root] = new_start
        component_end[root] = new_end
        accepted_edges.append((i, j, reason))

    components = {}
    for index in range(count):
        root = find(index)
        components.setdefault(root, []).append(index)

    groups = []

    for root, indexes in sorted(
        components.items(),
        key=lambda item: min(alerts[i]["epoch"] for i in item[1])
    ):
        if len(indexes) < 2:
            continue

        members = [alerts[i] for i in indexes]
        member_set = set(indexes)

        reasons = sorted({
            reason
            for i, j, reason in accepted_edges
            if i in member_set and j in member_set
        })

        members.sort(
            key=lambda item: (
                item["epoch"],
                str(item.get("wazuh_id") or "")
            )
        )

        distinct_rules = len({
            member.get("rule_id")
            for member in members
            if member.get("rule_id")
        })

        pairs = list(combinations(members, 2))

        has_shared_ip = any(
            a.get("source_ip")
            and a.get("source_ip") == b.get("source_ip")
            for a, b in pairs
        )
        has_shared_user = any(
            a.get("username")
            and a.get("username") == b.get("username")
            for a, b in pairs
        )
        has_shared_ip_account = any(
            a.get("source_ip")
            and a.get("source_ip") == b.get("source_ip")
            and a.get("username")
            and a.get("username") == b.get("username")
            for a, b in pairs
        )

        has_dns_transaction = any(
            "matching DNS query and response transaction" in reason
            for reason in reasons
        )
        has_process_link = any(
            "process ID" in reason or "parent-child" in reason
            for reason in reasons
        )
        has_attack_metadata = any(
            member.get("technique_ids") for member in members
        )

        # Correlation support only; not attack probability.
        score = 35
        score += min(20, (len(members) - 2) * 5)
        score += 20 if has_shared_ip_account else (8 if has_shared_ip else 0)
        score += 15 if has_shared_user else 0
        score += 10 if distinct_rules >= 2 else 0
        score += 5 if has_attack_metadata else 0
        score = min(score, 85)

        if has_dns_transaction and not has_process_link:
            title = "DNS query and response"
        elif has_process_link:
            title = "Correlated process and security events"
        else:
            title = "Correlated security events"

        classification, classification_reason = classify_candidate(
            members, reasons
        )

        groups.append({
            "status": "candidate_chain",
            "classification": classification,
            "classification_reason": classification_reason,
            "title": title,
            "agent": members[0].get("agent"),
            "start": members[0]["timestamp"],
            "end": members[-1]["timestamp"],
            "correlation_support_score": score,
            "score_note": (
                "Heuristic correlation support only; not attack "
                "probability or a model confidence score."
            ),
            "link_reasons": reasons,
            "alert_count": len(members),
            "alert_ids": [
                member["wazuh_id"] for member in members
            ],
            "source_document_ids": sorted({
                document_id
                for member in members
                for document_id in member.get(
                    "source_document_ids", [member["wazuh_id"]]
                )
            }),
            "technique_ids": sorted({
                technique
                for member in members
                for technique in member.get("technique_ids", [])
            }),
            "evidence": [
                evidence_projection(member) for member in members
            ],
            "hypothesis": (
                "These events may be related. Review the linked "
                "evidence before determining whether an attack occurred."
            ),
        })

    return groups

def investigate_recent_alerts(limit=MAX_ALERTS):
    """Read recent stored alerts and return candidate correlations."""
    limit = max(1, min(int(limit), MAX_ALERTS))

    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row

        rows = db.execute(
            """
            SELECT wazuh_id, timestamp, severity, rule_id, rule_level,
                   agent, agent_id, source_ip, description, evidence, raw_json
            FROM wazuh_alerts
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    stored_alerts = [extract_details(row) for row in rows]
    alerts = deduplicate_source_events(stored_alerts)
    candidates = correlate_alerts(alerts)

    return {
        "source": "existing SQLite Wazuh alert store",
        "alerts_examined": len(stored_alerts),
        "unique_events_examined": len(alerts),
        "duplicate_documents_skipped": len(stored_alerts) - len(alerts),
        "candidate_count": len(candidates),
        "candidates": candidates,
    }
