"""The agent's tool belt: small, self-contained lookups and heuristics.

Each function is a plain, independently testable Python callable. ``ToolRegistry``
wraps them with the name/description/JSON-schema shape both the deterministic
planner and a real Claude tool-use call need, so the same tool definitions
drive whichever planner is in use.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_json(name: str) -> dict:
    with open(DATA_DIR / name, encoding="utf-8") as fh:
        return json.load(fh)


# --- individual tools -------------------------------------------------------

def threat_intel_lookup(indicator: str, feed: dict | None = None) -> dict:
    """Check an indicator (IP, domain, hash) against the local threat-intel feed."""
    feed = feed if feed is not None else _load_json("threat_intel.json")["indicators"]
    hit = feed.get(indicator)
    if hit:
        return {"indicator": indicator, "is_malicious": True, **hit}
    return {
        "indicator": indicator,
        "is_malicious": False,
        "confidence": "none",
        "source": None,
        "notes": "Not present in the local threat-intel feed.",
    }


_SUSPICIOUS_COMMAND_PATTERNS = [
    (re.compile(r"-enc(odedcommand)?\s+[a-z0-9+/=]{16,}", re.I), "Base64-encoded PowerShell command"),
    (re.compile(r"mimikatz", re.I), "Reference to the Mimikatz credential-dumping tool"),
    (re.compile(r"certutil.*(-urlcache|-decode)", re.I), "certutil abused for download/decode"),
    (re.compile(r"invoke-webrequest|\biwr\b|\bwget\b|\bcurl\b", re.I), "Remote content retrieval from a script context"),
    (re.compile(r"schtasks|new-scheduledtask", re.I), "Scheduled task creation"),
    (re.compile(r"vssadmin.*delete shadows|wbadmin.*delete", re.I), "Shadow copy/backup deletion (ransomware precursor)"),
    (re.compile(r"net\s+(user|localgroup)\s+\S+.*\s+/add", re.I), "Local account or group manipulation"),
]


def process_reputation_lookup(process_name: str | None = None, command_line: str | None = None) -> dict:
    """Check a process name/command line for known-suspicious patterns."""
    text = f"{process_name or ''} {command_line or ''}"
    matches = [note for pattern, note in _SUSPICIOUS_COMMAND_PATTERNS if pattern.search(text)]
    return {
        "process_name": process_name,
        "command_line": command_line,
        "is_suspicious": bool(matches),
        "matched_patterns": matches,
    }


def asset_criticality_lookup(hostname: str | None, inventory: dict | None = None) -> dict:
    """Look up business criticality and owner for a hostname."""
    inventory = inventory if inventory is not None else _load_json("asset_inventory.json")["hosts"]
    if not hostname:
        return {"hostname": hostname, "known_asset": False, "criticality": "unknown", "owner": None, "environment": None}
    entry = inventory.get(hostname)
    if entry:
        return {"hostname": hostname, "known_asset": True, **entry}
    return {"hostname": hostname, "known_asset": False, "criticality": "unknown", "owner": None, "environment": None}


def user_baseline_check(user: str | None, hostname: str | None = None, baselines: dict | None = None) -> dict:
    """Check whether a user logging into a host matches their normal baseline."""
    baselines = baselines if baselines is not None else _load_json("user_baselines.json")["users"]
    if not user:
        return {"user": user, "hostname": hostname, "baseline_known": False, "is_deviation": False, "normal_hosts": []}
    normal_hosts = baselines.get(user, [])
    if not normal_hosts:
        return {"user": user, "hostname": hostname, "baseline_known": False, "is_deviation": False, "normal_hosts": []}
    is_deviation = hostname is not None and hostname not in normal_hosts
    return {"user": user, "hostname": hostname, "baseline_known": True, "is_deviation": is_deviation, "normal_hosts": normal_hosts}


def attack_technique_lookup(keywords: list[str], techniques: list[dict] | None = None) -> dict:
    """Map free-text findings keywords to relevant MITRE ATT&CK techniques."""
    techniques = techniques if techniques is not None else _load_json("attack_techniques.json")["techniques"]
    haystack = " | ".join(k for k in keywords if k).lower()
    matches = [t for t in techniques if any(kw.lower() in haystack for kw in t.get("keywords", []))]
    return {"keywords": list(keywords), "matches": matches}


# --- registry ----------------------------------------------------------------

@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict
    handler: Callable[..., dict]


class ToolRegistry:
    """Binds the tool functions to their JSON-schema specs for the planners."""

    def __init__(
        self,
        threat_intel: dict | None = None,
        asset_inventory: dict | None = None,
        user_baselines: dict | None = None,
        attack_techniques: list[dict] | None = None,
    ):
        self._threat_intel = threat_intel if threat_intel is not None else _load_json("threat_intel.json")["indicators"]
        self._asset_inventory = asset_inventory if asset_inventory is not None else _load_json("asset_inventory.json")["hosts"]
        self._user_baselines = user_baselines if user_baselines is not None else _load_json("user_baselines.json")["users"]
        self._attack_techniques = attack_techniques if attack_techniques is not None else _load_json("attack_techniques.json")["techniques"]

        self._specs = [
            ToolSpec(
                "threat_intel_lookup",
                "Check an indicator (IP, domain, hash) against the local threat-intel feed.",
                {"type": "object", "properties": {"indicator": {"type": "string"}}, "required": ["indicator"]},
                lambda indicator: threat_intel_lookup(indicator, self._threat_intel),
            ),
            ToolSpec(
                "process_reputation_lookup",
                "Check a process name/command line for known-suspicious execution patterns.",
                {
                    "type": "object",
                    "properties": {
                        "process_name": {"type": "string"},
                        "command_line": {"type": "string"},
                    },
                },
                lambda process_name=None, command_line=None: process_reputation_lookup(process_name, command_line),
            ),
            ToolSpec(
                "asset_criticality_lookup",
                "Look up the business criticality and owner of a hostname.",
                {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]},
                lambda hostname: asset_criticality_lookup(hostname, self._asset_inventory),
            ),
            ToolSpec(
                "user_baseline_check",
                "Check whether a user logging into a given host matches their normal baseline.",
                {
                    "type": "object",
                    "properties": {"user": {"type": "string"}, "hostname": {"type": "string"}},
                    "required": ["user"],
                },
                lambda user, hostname=None: user_baseline_check(user, hostname, self._user_baselines),
            ),
            ToolSpec(
                "attack_technique_lookup",
                "Map findings keywords (process names, pattern notes, incident description) to MITRE ATT&CK techniques.",
                {
                    "type": "object",
                    "properties": {"keywords": {"type": "array", "items": {"type": "string"}}},
                    "required": ["keywords"],
                },
                lambda keywords: attack_technique_lookup(keywords, self._attack_techniques),
            ),
        ]

    def specs(self) -> list[ToolSpec]:
        return list(self._specs)

    def call(self, name: str, arguments: dict) -> dict:
        for spec in self._specs:
            if spec.name == name:
                return spec.handler(**arguments)
        raise KeyError(f"Unknown tool: {name}")
