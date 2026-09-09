"""The agent's toolbox.

Every tool the SOC agent can call — live via Claude's tool-use API, or
offline via :mod:`soc_agent.offline_planner` — is a plain Python function
that takes a :class:`ToolContext` plus keyword arguments and returns a
JSON-serializable ``dict``. Keeping tools as ordinary functions (rather
than, say, methods spread across the agent class) means the exact same
implementations back both execution modes: the agent's "reasoning" may
differ between live and offline mode, but the ground truth it observes
never does.

``TOOL_SPECS`` describes each tool in Anthropic's tool-use JSON Schema
format, for the live agent loop. ``TOOL_DISPATCH`` maps tool names to
their implementations, for both loops.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class ToolContext:
    """Local data + case state the tools operate on. Loaded once per investigation."""

    threat_intel: dict[str, dict] = field(default_factory=dict)
    attack_techniques: list[dict] = field(default_factory=list)
    process_baseline: set[str] = field(default_factory=set)
    log_path: str | Path | None = None
    _log_lines_cache: list[str] | None = field(default=None, repr=False, compare=False)

    def log_lines(self) -> list[str]:
        if self._log_lines_cache is None:
            if self.log_path is None:
                self._log_lines_cache = []
            else:
                self._log_lines_cache = Path(self.log_path).read_text(encoding="utf-8").splitlines()
        return self._log_lines_cache

    @classmethod
    def load_default(cls, log_path: str | Path | None = None) -> "ToolContext":
        with open(DATA_DIR / "threat_intel.json", encoding="utf-8") as handle:
            intel_raw = json.load(handle)["indicators"]
        threat_intel = {entry["value"].lower(): entry for entry in intel_raw}

        with open(DATA_DIR / "attack_techniques.json", encoding="utf-8") as handle:
            attack_techniques = json.load(handle)["techniques"]

        with open(DATA_DIR / "process_baseline.json", encoding="utf-8") as handle:
            process_baseline = {name.lower() for name in json.load(handle)["known_good_processes"]}

        return cls(
            threat_intel=threat_intel,
            attack_techniques=attack_techniques,
            process_baseline=process_baseline,
            log_path=log_path,
        )


@dataclass
class Verdict:
    """The agent's final, structured conclusion for an investigation."""

    severity: str
    summary: str
    key_indicators: list[str]
    matched_techniques: list[str]
    recommended_actions: list[str]
    steps_taken: int = 0

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "summary": self.summary,
            "key_indicators": self.key_indicators,
            "matched_techniques": self.matched_techniques,
            "recommended_actions": self.recommended_actions,
            "steps_taken": self.steps_taken,
        }


def check_ioc_reputation(ctx: ToolContext, indicator: str) -> dict:
    """Look up an indicator (IP, domain, or hash) against the local threat-intel feed."""
    record = ctx.threat_intel.get(indicator.strip().lower())
    if record is None:
        return {
            "indicator": indicator,
            "known_malicious": False,
            "source": None,
            "confidence": None,
            "notes": "No match in local threat-intel feed.",
        }
    return {
        "indicator": indicator,
        "known_malicious": True,
        "source": record["source"],
        "confidence": record["confidence"],
        "notes": record["notes"],
    }


def search_logs(ctx: ToolContext, query: str, max_lines: int = 20) -> dict:
    """Grep the host log supplied for this investigation for a substring (IP, user, ...)."""
    if ctx.log_path is None:
        return {"query": query, "matched_lines": [], "total_matches": 0, "note": "No log file was provided for this investigation."}
    matched = [line for line in ctx.log_lines() if query.lower() in line.lower()]
    return {"query": query, "matched_lines": matched[:max_lines], "total_matches": len(matched)}


def lookup_attack_technique(ctx: ToolContext, keywords: str, top_k: int = 3) -> dict:
    """Match free-text keywords against a small local MITRE ATT&CK technique reference."""
    terms = {tok for tok in _simple_tokenize(keywords)}
    scored = []
    for technique in ctx.attack_techniques:
        overlap = terms & {kw.lower() for kw in technique["keywords"]}
        if overlap:
            scored.append((len(overlap), technique))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    matches = [
        {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "matched_keywords": sorted(terms & {kw.lower() for kw in t["keywords"]})}
        for _, t in scored[:top_k]
    ]
    return {"query_keywords": sorted(terms), "matches": matches}


def check_process_baseline(ctx: ToolContext, process_name: str) -> dict:
    """Check whether a process name is present in the host's known-good baseline."""
    known_good = process_name.strip().lower() in ctx.process_baseline
    return {
        "process": process_name,
        "known_good": known_good,
        "notes": "Present in host baseline allowlist." if known_good
        else "Not present in the baseline allowlist — verify legitimacy before dismissing.",
    }


def finish_investigation(
    ctx: ToolContext,
    severity: str,
    summary: str,
    key_indicators: list[str],
    matched_techniques: list[str],
    recommended_actions: list[str],
) -> dict:
    """Terminal tool: submit the final verdict and end the investigation loop."""
    severity = severity.strip().lower()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"severity must be one of {_VALID_SEVERITIES}, got {severity!r}")
    return {
        "severity": severity,
        "summary": summary,
        "key_indicators": list(key_indicators),
        "matched_techniques": list(matched_techniques),
        "recommended_actions": list(recommended_actions),
    }


def _simple_tokenize(text: str) -> list[str]:
    import re

    return [tok.lower() for tok in re.findall(r"[a-zA-Z]+", text)]


TOOL_DISPATCH = {
    "check_ioc_reputation": check_ioc_reputation,
    "search_logs": search_logs,
    "lookup_attack_technique": lookup_attack_technique,
    "check_process_baseline": check_process_baseline,
    "finish_investigation": finish_investigation,
}

TOOL_SPECS = [
    {
        "name": "check_ioc_reputation",
        "description": "Look up an IP, domain, or file hash against the local threat-intel feed to see if it is known malicious.",
        "input_schema": {
            "type": "object",
            "properties": {"indicator": {"type": "string", "description": "The IOC value to look up, e.g. an IP address or domain."}},
            "required": ["indicator"],
        },
    },
    {
        "name": "search_logs",
        "description": "Search the host log provided for this investigation for lines containing a substring, such as an IP address or username.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Substring to search for, e.g. an IP address or username."},
                "max_lines": {"type": "integer", "description": "Maximum number of matching lines to return.", "default": 20},
            },
            "required": ["query"],
        },
    },
    {
        "name": "lookup_attack_technique",
        "description": "Match free-text keywords describing observed behavior against a local MITRE ATT&CK technique reference.",
        "input_schema": {
            "type": "object",
            "properties": {
                "keywords": {"type": "string", "description": "Free text describing the observed activity, e.g. the alert text or a phrase."},
                "top_k": {"type": "integer", "description": "Maximum number of techniques to return.", "default": 3},
            },
            "required": ["keywords"],
        },
    },
    {
        "name": "check_process_baseline",
        "description": "Check whether a process name is present in the host's known-good process baseline/allowlist.",
        "input_schema": {
            "type": "object",
            "properties": {"process_name": {"type": "string", "description": "The process name to check, e.g. 'sshd' or 'mimikatz.exe'."}},
            "required": ["process_name"],
        },
    },
    {
        "name": "finish_investigation",
        "description": (
            "Conclude the investigation with a structured verdict. Call this exactly once, "
            "as your final action, only after gathering evidence with the other tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": list(_VALID_SEVERITIES), "description": "Overall severity of the finding."},
                "summary": {"type": "string", "description": "2-4 sentence summary of what happened and why it matters."},
                "key_indicators": {"type": "array", "items": {"type": "string"}, "description": "IPs, users, hashes, or processes central to the finding."},
                "matched_techniques": {"type": "array", "items": {"type": "string"}, "description": "MITRE ATT&CK technique IDs and names that apply, e.g. 'T1110 Brute Force'."},
                "recommended_actions": {"type": "array", "items": {"type": "string"}, "description": "2-4 concrete next steps for the on-call analyst."},
            },
            "required": ["severity", "summary", "key_indicators", "matched_techniques", "recommended_actions"],
        },
    },
]
