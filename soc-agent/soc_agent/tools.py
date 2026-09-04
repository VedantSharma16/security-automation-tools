"""Investigation tools available to the SOC agent.

Each function here is a plain, independently testable Python function. They
are exposed to the LLM as "tools" (see :mod:`soc_agent.schemas`) but are also
called directly by the deterministic offline planner in :mod:`soc_agent.agent`,
so the exact same investigative logic runs whether or not an LLM is driving
the loop.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Restricting domain matches to known TLDs cuts out false positives from
# filenames (auth.log, schtasks.exe) that otherwise satisfy the domain shape.
_KNOWN_TLDS = frozenset(
    """com net org io gov edu mil info biz co us uk ca de fr ru cn jp au nl
    br in it es se no fi dk pl ch at be nz ie za mx kr sg hk tw xyz top club
    online site app dev me tv cc ai eu asia name pro mobi tech cloud email
    live world group company network systems solutions services vip icu
    work link click download stream su int coop travel museum aero jobs""".split()
)

# Process name / command-line fragments that map to a MITRE technique.
_SUSPICIOUS_PROCESS_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"nc\s+-e|ncat\s+.*-e|/dev/tcp/"), "T1059", "Reverse/bind shell via netcat-style redirection"),
    (re.compile(r"powershell.*-enc|powershell.*-e\s|-EncodedCommand", re.I), "T1059", "Obfuscated/encoded PowerShell execution"),
    (re.compile(r"wget\s+http|curl\s+.*http.*-o\s|curl\s+-O", re.I), "T1105", "Tool/payload download over HTTP(S)"),
    (re.compile(r"mimikatz", re.I), "T1078", "Credential dumping tooling (Mimikatz)"),
    (re.compile(r"crontab\s+-e|/etc/cron\.|schtasks", re.I), "T1053", "Scheduled task/cron persistence mechanism"),
    (re.compile(r"chmod\s+\+s|setuid|sudo\s+su\s*$"), "T1068", "Privilege escalation via SUID/sudo manipulation"),
    (re.compile(r"base64\s+-d|echo\s+.*\|\s*bash", re.I), "T1059", "Obfuscated shell execution via base64/pipe-to-shell"),
]

_FAILED_LOGIN_RE = re.compile(
    r"Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_SUDO_RE = re.compile(r"sudo:\s*(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)")

_BRUTE_FORCE_THRESHOLD = 4


def _load_json(name: str) -> Any:
    with open(_DATA_DIR / name, encoding="utf-8") as handle:
        return json.load(handle)


def extract_iocs(text: str) -> dict:
    """Extract IPs, domains, and hashes from free-text alert/log content.

    Handles common "defanging" (``185[.]220[.]101[.]45``, ``hxxp://``) so
    indicators pasted from a report still get picked up.
    """
    normalized = (
        text.replace("[.]", ".").replace("(.)", ".").replace(" dot ", ".")
    )
    normalized = re.sub(r"hxxp", "http", normalized, flags=re.I)

    ips = sorted(set(_IP_RE.findall(normalized)))
    hashes = sorted(set(_HASH_RE.findall(normalized)))

    domains = set()
    for match in _DOMAIN_RE.findall(normalized):
        if match in ips:
            continue
        # Skip things that are actually part of a hash or version string.
        if re.fullmatch(r"[a-fA-F0-9.]+", match):
            continue
        tld = match.rsplit(".", 1)[-1].lower()
        if tld not in _KNOWN_TLDS:
            continue
        domains.add(match.lower())

    return {"ips": ips, "domains": sorted(domains), "hashes": hashes}


def check_threat_intel(indicator: str, category: str) -> dict:
    """Look up a single indicator against the bundled local threat-intel feed.

    ``category`` must be one of ``"ip"``, ``"domain"``, or ``"hash"``.
    """
    key_map = {"ip": "ips", "domain": "domains", "hash": "hashes"}
    if category not in key_map:
        raise ValueError(f"Unknown indicator category: {category!r}")

    feed = _load_json("threat_intel.json")
    bucket = feed.get(key_map[category], {})
    hit = bucket.get(indicator)
    if hit is None:
        return {
            "indicator": indicator,
            "category": category,
            "is_known_malicious": False,
            "confidence": "unknown",
            "notes": "No match in local threat-intel feed.",
        }
    return {
        "indicator": indicator,
        "category": category,
        "is_known_malicious": True,
        "confidence": hit["confidence"],
        "source": hit["source"],
        "notes": hit["notes"],
    }


def analyze_auth_log(log_text: str) -> dict:
    """Run correlated rule-based detection over auth-log style text.

    Detects: brute-force attempts (many failed logins from one source),
    likely credential compromise (failed logins followed by a success from
    the same source), and privilege escalation (sudo activity).
    """
    findings: list[dict] = []
    failed_by_ip: Counter[str] = Counter()
    succeeded_ips: set[str] = set()

    for line in log_text.splitlines():
        failed = _FAILED_LOGIN_RE.search(line)
        if failed:
            failed_by_ip[failed.group("ip")] += 1
            continue
        accepted = _ACCEPTED_LOGIN_RE.search(line)
        if accepted:
            succeeded_ips.add(accepted.group("ip"))
            continue
        sudo = _SUDO_RE.search(line)
        if sudo:
            findings.append(
                {
                    "type": "privilege_escalation",
                    "technique_id": "T1068",
                    "detail": f"sudo command by {sudo.group('user')}: {sudo.group('command').strip()}",
                }
            )

    for ip, count in failed_by_ip.items():
        if count >= _BRUTE_FORCE_THRESHOLD:
            findings.append(
                {
                    "type": "brute_force",
                    "technique_id": "T1110",
                    "detail": f"{count} failed login attempts from {ip}",
                    "source_ip": ip,
                }
            )
        if ip in succeeded_ips:
            findings.append(
                {
                    "type": "likely_compromise",
                    "technique_id": "T1078",
                    "detail": f"{count} failed attempt(s) from {ip} followed by a successful login",
                    "source_ip": ip,
                }
            )

    return {"findings": findings}


def check_process_list(processes: list[str]) -> dict:
    """Flag suspicious process command lines against a small local ruleset."""
    hits = []
    for proc in processes:
        for pattern, technique_id, description in _SUSPICIOUS_PROCESS_RULES:
            if pattern.search(proc):
                hits.append(
                    {
                        "process": proc,
                        "technique_id": technique_id,
                        "reason": description,
                    }
                )
                break
    return {"suspicious": hits}


def lookup_mitre_technique(technique_id: str) -> dict:
    """Return the local MITRE ATT&CK reference entry for a technique id."""
    techniques = _load_json("mitre_techniques.json")
    for technique in techniques:
        if technique["id"] == technique_id:
            return technique
    return {"id": technique_id, "name": "Unknown technique", "tactic": "", "description": ""}


TOOL_REGISTRY = {
    "extract_iocs": extract_iocs,
    "check_threat_intel": check_threat_intel,
    "analyze_auth_log": analyze_auth_log,
    "check_process_list": check_process_list,
    "lookup_mitre_technique": lookup_mitre_technique,
}
