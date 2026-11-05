"""MITRE ATT&CK technique mapping for each finding type.

Mapping findings to ATT&CK lets analysts pivot straight into detection
engineering, threat-intel and reporting workflows that are keyed on technique IDs.
"""

from __future__ import annotations

from typing import TypedDict


class Technique(TypedDict):
    id: str
    name: str
    tactic: str


MITRE_MAP: dict[str, list[Technique]] = {
    "brute_force": [
        {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    ],
    "password_spraying": [
        {"id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    ],
    "compromise_after_brute_force": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "privilege_escalation": [
        {
            "id": "T1548.003",
            "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            "tactic": "Privilege Escalation",
        },
    ],
    "persistence_root_account": [
        {"id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence"},
    ],
    "persistence_crontab": [
        {"id": "T1053.003", "name": "Scheduled Task/Job: Cron", "tactic": "Persistence"},
    ],
}


def techniques_for(finding_type: str) -> list[Technique]:
    """Return ATT&CK techniques for a finding type (empty list if unmapped)."""
    return [dict(t) for t in MITRE_MAP.get(finding_type, [])]  # type: ignore[misc]
