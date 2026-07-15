"""Heuristic indicator scoring, severity classification, and playbook lookups.

These heuristics are deliberately independent of the LLM narrator: severity is
always computed the same, deterministic way so the pipeline stays testable and
usable even with no API key configured.
"""

import re
from typing import List, Tuple

from .models import Alert

OFFENSIVE_TOOLS = {
    "mimikatz", "cobaltstrike", "cobalt strike", "metasploit", "psexec",
    "bloodhound", "impacket", "secretsdump", "crackmapexec", "rubeus",
    "kerberoast", "evil-winrm", "responder", "sharpdump", "sharpwmi",
    "hydra", "hashdump", "beacon.dll",
}

_OBFUSCATION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"-enc(odedcommand)?\b", re.I), "encoded PowerShell command"),
    (re.compile(r"frombase64string", re.I), "base64-decoded payload"),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.I), "hidden window flag"),
    (re.compile(r"\biex\s*\(", re.I), "Invoke-Expression of remote content"),
    (re.compile(r"downloadstring|invoke-webrequest", re.I), "remote payload download"),
]

_SUSPICIOUS_PATH_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\\windows\\temp\\|\\appdata\\|/tmp/|/dev/shm/", re.I), "execution from a temp/user-writable directory"),
    (re.compile(r"\bonlogon\b|\bonstart\b", re.I), "persistence triggered on logon/startup"),
]

TACTIC_PLAYBOOKS = {
    "Credential Access": [
        "Force a password reset for the affected account(s)",
        "Rotate any secrets/tokens the account had access to",
        "Hunt for lateral movement using the harvested credentials",
    ],
    "Execution": [
        "Isolate the host from the network",
        "Capture a memory/process dump for forensics before killing the process",
        "Review the parent process lineage",
    ],
    "Command and Control": [
        "Block the destination IP/domain at the perimeter",
        "Inspect outbound proxy/DNS logs for beaconing patterns",
    ],
    "Defense Evasion": [
        "Verify EDR/AV tamper protection is intact",
        "Check for disabled logging or cleared event logs",
    ],
    "Discovery": [
        "Correlate with authentication logs for follow-on activity",
        "Watch for a subsequent lateral movement attempt from the same source",
    ],
    "Reconnaissance": [
        "Confirm whether the scan source is an authorized asset",
        "Rate-limit or block the source if unauthorized",
    ],
    "Lateral Movement": [
        "Isolate the affected hosts",
        "Reset credentials used for the movement",
        "Review network segmentation between the hosts involved",
    ],
    "Persistence": [
        "Enumerate and remove the persistence mechanism",
        "Check for other footholds established around the same time",
    ],
    "Exfiltration": [
        "Identify what data left and to where",
        "Block the destination service if unauthorized",
    ],
    "default": [
        "Escalate to an on-call analyst for manual review",
        "Correlate with SIEM data for related events",
    ],
}


def score_indicators(alert: Alert) -> Tuple[List[str], float]:
    """Flag known offensive-tool references and obfuscation patterns in an alert."""
    text = alert.text().lower()
    indicators: List[str] = []
    score = 0.0

    for tool in OFFENSIVE_TOOLS:
        if tool in text:
            indicators.append(f"offensive tool reference: {tool}")
            score += 0.6

    for pattern, label in _OBFUSCATION_PATTERNS:
        if pattern.search(text):
            indicators.append(f"obfuscation indicator: {label}")
            score += 0.25

    for pattern, label in _SUSPICIOUS_PATH_PATTERNS:
        if pattern.search(text):
            indicators.append(f"suspicious indicator: {label}")
            score += 0.2

    return indicators, min(score, 1.0)


def classify_severity(risk_score: float) -> str:
    if risk_score >= 0.75:
        return "critical"
    if risk_score >= 0.4:
        return "high"
    if risk_score >= 0.2:
        return "medium"
    return "low"


def recommended_actions_for(tactic: str) -> List[str]:
    return TACTIC_PLAYBOOKS.get(tactic, TACTIC_PLAYBOOKS["default"])
