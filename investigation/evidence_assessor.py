"""Deterministic, evidence-bounded ATT&CK assessment and remediation."""

def assess_evidence(candidate):
    """Extract evidence-backed observations without asserting an attack."""
    evidence = [
        item for item in candidate.get("evidence", [])
        if isinstance(item, dict) and item.get("wazuh_id")
    ]
    findings = []

    def add(key, title, observation, limitation, items):
        ids = sorted({
            str(item["wazuh_id"])
            for item in items if item.get("wazuh_id")
        })
        if ids:
            findings.append({
                "finding_id": key,
                "title": title,
                "claim_type": "observed",
                "observation": observation,
                "limitations": limitation,
                "alert_ids": ids,
                "attack_technique_ids": [],
                "status": "evidence_observed",
            })

    def matching(rule_ids):
        return [
            item for item in evidence
            if str(item.get("rule_id", "")) in rule_ids
        ]

    failures = matching({"5710", "5712", "5760"})
    successes = matching({"5715"})
    pam = matching({"5503"})
    sudo = matching({"5401"})
    su = matching({"5301"})

    if failures:
        add(
            "ssh_authentication_failures",
            "SSH authentication failures",
            f"{len(failures)} failed SSH authentication event(s) observed.",
            "Failures alone do not establish successful access or password guessing.",
            failures,
        )

    if successes:
        add(
            "ssh_authentication_success",
            "Successful SSH authentication",
            f"{len(successes)} successful SSH authentication event(s) observed.",
            "Successful authentication alone does not establish adversary activity.",
            successes,
        )

    if pam:
        add(
            "pam_authentication_failures",
            "PAM authentication failures",
            f"{len(pam)} PAM authentication failure event(s) observed.",
            "These events do not establish successful authentication or escalation.",
            pam,
        )

    if sudo:
        add(
            "sudo_failures",
            "Failed sudo attempts",
            f"{len(sudo)} failed sudo event(s) observed.",
            "A failed sudo attempt does not establish privilege escalation.",
            sudo,
        )

    if su:
        add(
            "su_failures",
            "Failed su authentication",
            f"{len(su)} failed su event(s) observed.",
            "These events do not establish a successful user switch.",
            su,
        )

    dns = [
        item for item in evidence
        if any(item.get(k) not in (None, "", []) for k in (
            "dns_domain", "dns_query_type", "dns_answers",
            "response_code", "response_code_name"
        ))
    ]
    if dns:
        domains = sorted({
            str(item["dns_domain"])
            for item in dns if item.get("dns_domain")
        })
        add(
            "dns_telemetry_observed",
            "DNS telemetry observed",
            f"{len(dns)} DNS event(s) observed. Domains: "
            + (", ".join(domains[:10]) if domains else "not available"),
            "DNS telemetry alone does not establish malicious communication.",
            dns,
        )

    processes = [
        item for item in evidence
        if any(item.get(k) not in (None, "", []) for k in (
            "command", "process_name", "executable",
            "process_id", "parent_process_id"
        ))
    ]
    if processes:
        add(
            "process_telemetry_observed",
            "Process and command telemetry observed",
            f"{len(processes)} event(s) contain process or command metadata.",
            "A process name or command alone does not establish malicious execution.",
            processes,
        )

    return findings


def deterministic_remediation(candidate):
    evidence = [
        item for item in candidate.get("evidence", [])
        if isinstance(item, dict) and item.get("wazuh_id")
    ]

    if candidate.get("classification") in {"routine_activity", "inconclusive"}:
        return []

    def alert_ids(items):
        return sorted({str(item["wazuh_id"]) for item in items if item.get("wazuh_id")})

    def matching(rule_ids):
        return [
            item for item in evidence
            if str(item.get("rule_id", "")) in rule_ids
        ]

    recommendations = []

    # SSH authentication failures.
    ssh_failures = matching({"5710", "5712", "5760"})

    # SSH authentication success.
    ssh_successes = matching({"5715"})

    if ssh_failures and ssh_successes:
        failure_accounts = {
            str(item.get("username") or "").strip().lower()
            for item in ssh_failures
        }
        success_accounts = {
            str(item.get("username") or "").strip().lower()
            for item in ssh_successes
        }
        failure_sources = {
            str(item.get("src_ip") or item.get("source_ip") or "").strip()
            for item in ssh_failures
        }
        success_sources = {
            str(item.get("src_ip") or item.get("source_ip") or "").strip()
            for item in ssh_successes
        }

        same_account = bool(
            (failure_accounts - {""}) & (success_accounts - {""})
        )
        same_source = bool(
            (failure_sources - {""}) & (success_sources - {""})
        )

        if same_account and same_source:
            ids = alert_ids(ssh_failures + ssh_successes)
            recommendations.append({
                "action": (
                    "Verify whether the successful SSH authentication was "
                    "expected, then review the resulting session activity."
                ),
                "rationale": (
                    "The evidence contains SSH authentication failures and "
                    "a successful SSH authentication sharing an account and "
                    "source address. This sequence warrants review but does "
                    "not by itself establish unauthorized access."
                ),
                "alert_ids": ids,
                "status": "advisory_only",
            })
        else:
            recommendations.append({
                "action": (
                    "Review the SSH authentication failures and successful "
                    "login separately, verifying the account and source "
                    "address for each event."
                ),
                "rationale": (
                    "The evidence contains both failed and successful SSH "
                    "authentication events, but a matching account and "
                    "source could not be established."
                ),
                "alert_ids": alert_ids(ssh_failures + ssh_successes),
                "status": "advisory_only",
            })

    elif ssh_failures:
        nonexistent = [
            item for item in ssh_failures
            if str(item.get("rule_id", "")) in {"5710", "5712"}
            or "non existent user" in str(item.get("description", "")).lower()
            or "nonexistent user" in str(item.get("description", "")).lower()
        ]

        if nonexistent:
            recommendations.append({
                "action": (
                    "Verify whether the nonexistent-account SSH attempts "
                    "were generated by an authorized test or expected activity."
                ),
                "rationale": (
                    "The evidence identifies SSH attempts involving a "
                    "nonexistent account. This does not establish a valid "
                    "account login or successful access."
                ),
                "alert_ids": alert_ids(nonexistent),
                "status": "advisory_only",
            })

        other_failures = [
            item for item in ssh_failures if item not in nonexistent
        ]

        if other_failures:
            recommendations.append({
                "action": (
                    "Review the SSH authentication failures and verify "
                    "the account, source, frequency, and authentication outcome."
                ),
                "rationale": (
                    "The supplied evidence contains SSH authentication "
                    "failures. These events alone do not establish successful "
                    "access or account compromise."
                ),
                "alert_ids": alert_ids(other_failures),
                "status": "advisory_only",
            })

    elif ssh_successes:
        recommendations.append({
            "action": (
                "Verify that the SSH login was expected and review the "
                "associated session activity if it was not."
            ),
            "rationale": (
                "A successful SSH authentication is observed. Success alone "
                "does not establish malicious activity."
            ),
            "alert_ids": alert_ids(ssh_successes),
            "status": "advisory_only",
        })

    # PAM authentication failures are not automatically sudo failures.
    pam_failures = matching({"5503"})

    if pam_failures:
        recommendations.append({
            "action": (
                "Review the corresponding authentication records to identify "
                "the account, authentication service, and reason for failure."
            ),
            "rationale": (
                "The evidence contains PAM authentication failure events. "
                "These events alone do not establish successful access or "
                "privilege escalation."
            ),
            "alert_ids": alert_ids(pam_failures),
            "status": "advisory_only",
        })

    # Failed sudo execution is handled separately.
    sudo_failures = matching({"5401"})

    if sudo_failures:
        recommendations.append({
            "action": (
                "Inspect the failed sudo attempt, including the requested "
                "command, invoking account, and process context."
            ),
            "rationale": (
                "The evidence records a failed sudo attempt. It does not "
                "establish successful privilege escalation."
            ),
            "alert_ids": alert_ids(sudo_failures),
            "status": "advisory_only",
        })

    # Failed su authentication is distinct from sudo.
    su_failures = matching({"5301"})

    if su_failures:
        recommendations.append({
            "action": (
                "Review the failed su authentication attempt and verify "
                "which account and process initiated it."
            ),
            "rationale": (
                "The evidence records a failed authentication attempt "
                "associated with a UID change. It does not establish "
                "a successful user switch."
            ),
            "alert_ids": alert_ids(su_failures),
            "status": "advisory_only",
        })

    return recommendations[:5]
