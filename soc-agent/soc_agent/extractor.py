"""Minimal indicator extraction: pulls candidate IPs, domains, and process
names out of raw alert text so the agent has something concrete to
investigate before it starts reasoning about which tools to call.

Deliberately small — this is a seed for the agent's plan, not a
full-precision IOC pipeline. See ``ioc-triage-assistant/`` elsewhere in this
repo for a more thorough defang-aware extractor with false-positive
filtering.
"""

from __future__ import annotations

import re

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|io|co|biz|ru|cn|xyz)\b",
    re.IGNORECASE,
)

# Common Windows/Linux process names the extractor recognizes when they
# appear as bare tokens in alert text (e.g. "powershell.exe spawned by ...").
_PROCESS_RE = re.compile(
    r"\b[\w.-]+\.exe\b|\b(?:sshd|systemd|nginx|cron|bash|mimikatz)\b",
    re.IGNORECASE,
)

_PRIVATE_IP_PREFIXES = ("10.", "172.16.", "192.168.", "127.")


def _is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE_IP_PREFIXES)


def extract_seed_indicators(alert_text: str) -> dict:
    """Extract a small seed set of candidate indicators from alert text.

    Returns a dict with keys ``ips`` (public IPv4s only), ``domains``, and
    ``processes`` — each a de-duplicated, order-preserving list of strings.
    """
    ips = []
    for match in _IPV4_RE.findall(alert_text):
        if not _is_private(match) and match not in ips:
            ips.append(match)

    domains = []
    for match in _DOMAIN_RE.findall(alert_text):
        domain = match.lower()
        if domain not in domains:
            domains.append(domain)

    processes = []
    for match in _PROCESS_RE.findall(alert_text):
        proc = match.lower()
        if proc not in processes:
            processes.append(proc)

    return {"ips": ips, "domains": domains, "processes": processes}
