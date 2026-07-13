"""Map offensive-security tool names / commands found in text to MITRE
ATT&CK techniques, so a triage report gives an analyst a starting point
instead of a bare keyword hit.

This is a curated, intentionally small lookup table (not a replacement for a
real detection engineering pipeline) meant to add context during manual
report/log triage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


@dataclass
class AttackHit:
    keyword: str
    tactic: str
    technique_id: str | None
    technique_name: str


# keyword -> (tactic, technique_id, technique_name)
# technique_id is None for tools that are dual-use recon/offensive utilities
# without a single canonical ATT&CK enterprise technique.
_ATTACK_MAP: dict[str, tuple[str, str | None, str]] = {
    "mimikatz": ("Credential Access", "T1003", "OS Credential Dumping"),
    "secretsdump": ("Credential Access", "T1003", "OS Credential Dumping"),
    "hashdump": ("Credential Access", "T1003", "OS Credential Dumping"),
    "kerberoast": ("Credential Access", "T1558.003", "Kerberoasting"),
    "rubeus": ("Credential Access", "T1558.003", "Kerberoasting"),
    "responder": ("Credential Access", "T1557", "Adversary-in-the-Middle"),
    "crackmapexec": ("Lateral Movement", "T1021", "Remote Services"),
    "evilwinrm": ("Lateral Movement", "T1021.006", "Windows Remote Management"),
    "psexec": ("Execution", "T1569.002", "System Services: Service Execution"),
    "powershell": ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "powershell_ise": ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "cmd.exe": ("Execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    "wmic": ("Execution", "T1047", "Windows Management Instrumentation"),
    "wmic.exe": ("Execution", "T1047", "Windows Management Instrumentation"),
    "certutil": ("Command and Control", "T1105", "Ingress Tool Transfer"),
    "certutil.exe": ("Command and Control", "T1105", "Ingress Tool Transfer"),
    "bitsadmin": ("Defense Evasion", "T1197", "BITS Jobs"),
    "regsvr32": ("Defense Evasion", "T1218.010", "System Binary Proxy Execution: Regsvr32"),
    "schtasks": ("Persistence", "T1053.005", "Scheduled Task"),
    "cobaltstrike": ("Command and Control", "T1071", "Application Layer Protocol"),
    "metasploit": ("Resource Development", None, "Exploitation framework"),
    "impacket": ("Execution", None, "Offensive toolkit (SMB/RPC/Kerberos abuse)"),
    "bloodhound": ("Discovery", "T1482", "Domain Trust Discovery"),
    "netcat": ("Command and Control", "T1571", "Non-Standard Port"),
    "nc.exe": ("Command and Control", "T1571", "Non-Standard Port"),
    "ncat": ("Command and Control", "T1571", "Non-Standard Port"),
    "proxychains": ("Command and Control", "T1090", "Proxy"),
    "tcpdump": ("Discovery", "T1040", "Network Sniffing"),
    "wireshark": ("Discovery", "T1040", "Network Sniffing"),
    "nmap": ("Reconnaissance", None, "Active network/service scanning"),
    "masscan": ("Reconnaissance", None, "Active network/service scanning"),
    "gobuster": ("Reconnaissance", "T1595.003", "Active Scanning: Wordlist Scanning"),
    "dirbuster": ("Reconnaissance", "T1595.003", "Active Scanning: Wordlist Scanning"),
    "sqlmap": ("Initial Access", None, "Automated SQL injection exploitation"),
    "hydra": ("Credential Access", "T1110", "Brute Force"),
    "johntheripper": ("Credential Access", "T1110.002", "Brute Force: Password Cracking"),
    "aircrack-ng": ("Credential Access", "T1110.002", "Brute Force: Password Cracking"),
    "taskkill": ("Impact", "T1489", "Service Stop"),
    "regedit": ("Defense Evasion", "T1112", "Modify Registry"),
    "dumpsec": ("Discovery", None, "Windows security/permissions enumeration"),
}


def enrich(text: str) -> list[AttackHit]:
    """Scan text for known offensive-tool keywords and return ATT&CK context
    for each unique hit, in first-seen order."""
    lowered = text.lower()
    hits: list[AttackHit] = []
    seen = set()
    for keyword, (tactic, technique_id, technique_name) in _ATTACK_MAP.items():
        pattern = r"\b" + re.escape(keyword) + r"\b"
        if keyword in seen:
            continue
        if re.search(pattern, lowered):
            hits.append(AttackHit(keyword, tactic, technique_id, technique_name))
            seen.add(keyword)
    return hits


def attack_url(technique_id: str) -> str:
    return ATTACK_URL.format(technique_id.split(".")[0])
