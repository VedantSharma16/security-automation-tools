"""Lightweight auth-log analysis: brute force, compromise, and post-exploitation signals.

This is intentionally a compact, self-contained rule set (not a full syslog
parser) — it exists as one *tool* the agent can call mid-investigation when
the incident text contains raw log lines, not as a standalone log-analysis
product. For a deeper, temporally-correlated version of this same idea, see
``../log-triage-assistant``.
"""

from __future__ import annotations

import re
from collections import defaultdict

_FAILED_PW_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
_ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)")
_SUDO_RE = re.compile(r"sudo:.*COMMAND=(?P<command>.*)")
_USERADD_RE = re.compile(r"new user:\s*name=(?P<name>[^,]+),\s*UID=(?P<uid>\d+)")
_CRONTAB_RE = re.compile(r"crontab.*\((?P<user>\S+)\)\s*(?P<action>REPLACE|BEGIN EDIT|END EDIT)")

BRUTE_FORCE_THRESHOLD = 4


def looks_like_auth_log(text: str) -> bool:
    """Heuristic sniff test used by the offline orchestrator to decide whether
    this tool is even applicable to a given piece of incident text."""
    return bool(
        _FAILED_PW_RE.search(text)
        or _ACCEPTED_RE.search(text)
        or _SUDO_RE.search(text)
        or "sshd" in text
    )


def analyze_auth_log(text: str) -> dict:
    """Scan raw auth-log-style text and return structured findings.

    Returns a dict with:
      - failed_logins_by_ip: {ip: count}
      - brute_force_ips: IPs with failed_logins_by_ip[ip] >= BRUTE_FORCE_THRESHOLD
      - accepted_logins: [{user, ip}]
      - likely_compromised_ips: accepted-login IPs that also appear in
        brute_force_ips (successful login after repeated failures)
      - privilege_escalation: [command strings run via sudo]
      - persistence_events: [{"type": "useradd"|"crontab", ...}]
    """
    failed_by_ip: dict[str, int] = defaultdict(int)
    accepted: list[dict] = []
    sudo_commands: list[str] = []
    persistence: list[dict] = []

    for line in text.splitlines():
        m = _FAILED_PW_RE.search(line)
        if m:
            failed_by_ip[m.group("ip")] += 1
            continue

        m = _ACCEPTED_RE.search(line)
        if m:
            accepted.append({"user": m.group("user"), "ip": m.group("ip")})
            continue

        m = _SUDO_RE.search(line)
        if m:
            sudo_commands.append(m.group("command").strip())
            continue

        m = _USERADD_RE.search(line)
        if m:
            persistence.append(
                {"type": "useradd", "name": m.group("name").strip(), "uid": int(m.group("uid"))}
            )
            continue

        m = _CRONTAB_RE.search(line)
        if m:
            persistence.append(
                {"type": "crontab", "user": m.group("user"), "action": m.group("action")}
            )

    brute_force_ips = sorted(
        ip for ip, count in failed_by_ip.items() if count >= BRUTE_FORCE_THRESHOLD
    )
    likely_compromised_ips = sorted(
        {entry["ip"] for entry in accepted if entry["ip"] in brute_force_ips}
    )

    return {
        "failed_logins_by_ip": dict(sorted(failed_by_ip.items())),
        "brute_force_ips": brute_force_ips,
        "accepted_logins": accepted,
        "likely_compromised_ips": likely_compromised_ips,
        "privilege_escalation": sudo_commands,
        "persistence_events": persistence,
    }
