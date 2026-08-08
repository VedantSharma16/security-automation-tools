"""The agent's tool belt: local, offline lookups the investigation loop can call.

Each tool is a small, pure-ish function backed by a bundled JSON dataset
(threat intel, an asset inventory, prior alert history, and a MITRE ATT&CK
keyword-to-playbook map) plus a :class:`ToolSpec` describing it. The same
specs are used to build the Anthropic tool-calling schema for the live LLM
agent (see ``llm_agent.py``) and to document what the offline planner is
allowed to call (see ``planner.py``) — one registry, two callers.

No network access, no external services: swap the ``_load_*`` functions for
calls to a real SIEM/EDR/threat-intel API to go live.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load(name: str, data_dir: Path | str | None = None) -> dict:
    directory = Path(data_dir) if data_dir else DATA_DIR
    with open(directory / name, encoding="utf-8") as handle:
        return json.load(handle)


# --------------------------------------------------------------------------
# Tool implementations
# --------------------------------------------------------------------------

def lookup_indicator_reputation(indicator: str, data_dir: Path | str | None = None) -> dict:
    """Check an IP/domain indicator against the local threat-intel feed."""
    intel = _load("threat_intel.json", data_dir)
    needle = indicator.strip().lower()
    for entry in intel.get("indicators", []):
        if entry["value"].lower() == needle:
            is_malicious = entry["confidence"] != "none"
            return {
                "indicator": indicator,
                "found": True,
                "is_known_malicious": is_malicious,
                "confidence": entry["confidence"],
                "source": entry["source"],
                "notes": entry["notes"],
            }
    return {
        "indicator": indicator,
        "found": False,
        "is_known_malicious": False,
        "confidence": None,
        "source": None,
        "notes": "No match in local threat-intel feed.",
    }


def get_asset_context(host: str, data_dir: Path | str | None = None) -> dict:
    """Look up an asset's criticality/owner/environment from the local inventory."""
    inventory = _load("asset_inventory.json", data_dir)
    needle = host.strip().lower()
    for asset in inventory.get("assets", []):
        if asset["host"].lower() == needle or asset.get("ip") == host:
            return {"host": host, "found": True, **{k: v for k, v in asset.items() if k != "host"}}
    return {
        "host": host,
        "found": False,
        "ip": None,
        "criticality": "unknown",
        "owner": None,
        "environment": None,
        "os": None,
        "notes": "Host not present in asset inventory.",
    }


def search_alert_history(indicator: str, data_dir: Path | str | None = None) -> dict:
    """Search prior alert outcomes for this indicator to spot recurring activity."""
    history = _load("alert_history.json", data_dir)
    needle = indicator.strip().lower()
    matches = [h for h in history.get("history", []) if h["indicator"].lower() == needle]
    true_positive_count = sum(1 for m in matches if m["verdict"] == "true_positive")
    false_positive_count = sum(1 for m in matches if m["verdict"] == "false_positive")
    return {
        "indicator": indicator,
        "prior_alert_count": len(matches),
        "prior_true_positive_count": true_positive_count,
        "prior_false_positive_count": false_positive_count,
        "matches": matches,
    }


def map_mitre_technique(text: str, data_dir: Path | str | None = None) -> dict:
    """Keyword-match alert narrative text against a small ATT&CK playbook map."""
    playbooks = _load("mitre_playbooks.json", data_dir)
    haystack = text.lower()
    matches = []
    for technique in playbooks.get("techniques", []):
        hit_keywords = [kw for kw in technique["keywords"] if kw in haystack]
        if hit_keywords:
            matches.append(
                {
                    "id": technique["id"],
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "matched_keywords": hit_keywords,
                    "recommended_actions": technique["recommended_actions"],
                }
            )
    matches.sort(key=lambda m: len(m["matched_keywords"]), reverse=True)
    return {"matched": bool(matches), "techniques": matches}


def calculate_risk_score(signals: dict) -> dict:
    """Deterministically combine investigation signals into a 0-100 risk score.

    Pure function, no I/O — this is the scoring rubric both the offline
    planner and the live LLM agent are required to use, so two runs over the
    same evidence always land on the same number.
    """
    score = 0
    reasons: list[str] = []

    if signals.get("any_known_malicious"):
        score += 40
        reasons.append("indicator matched local threat-intel feed")
        if signals.get("max_confidence") == "high":
            score += 15
            reasons.append("threat-intel match confidence is high")

    criticality = signals.get("asset_criticality", "unknown")
    if criticality == "critical":
        score += 20
        reasons.append("affected asset criticality is critical")
    elif criticality == "high":
        score += 10
        reasons.append("affected asset criticality is high")

    if signals.get("recurring_true_positive"):
        score += 15
        reasons.append("indicator has prior true-positive history")

    if signals.get("seen_before_as_benign_only"):
        score -= 15
        reasons.append("indicator has only ever been closed as false-positive before")

    if signals.get("technique_matched"):
        score += 10
        reasons.append("alert narrative matches a known ATT&CK technique")

    score = max(0, min(100, score))
    if score >= 80:
        band = "critical"
    elif score >= 60:
        band = "high"
    elif score >= 35:
        band = "medium"
    else:
        band = "low"

    return {"score": score, "band": band, "reasons": reasons}


# --------------------------------------------------------------------------
# Tool registry (shared by the offline planner and the live LLM agent)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[..., dict]

    def to_anthropic_schema(self) -> dict:
        return {"name": self.name, "description": self.description, "input_schema": self.parameters}


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        name="lookup_indicator_reputation",
        description="Check whether an IP or domain indicator is known-malicious in the local threat-intel feed.",
        parameters={
            "type": "object",
            "properties": {"indicator": {"type": "string", "description": "IP address or domain to look up."}},
            "required": ["indicator"],
        },
        handler=lookup_indicator_reputation,
    ),
    ToolSpec(
        name="get_asset_context",
        description="Look up an internal host's criticality, owner, and environment in the asset inventory.",
        parameters={
            "type": "object",
            "properties": {"host": {"type": "string", "description": "Hostname or IP of the internal asset."}},
            "required": ["host"],
        },
        handler=get_asset_context,
    ),
    ToolSpec(
        name="search_alert_history",
        description="Search prior alert outcomes for this indicator to check for recurring true/false-positive activity.",
        parameters={
            "type": "object",
            "properties": {"indicator": {"type": "string", "description": "Indicator to search alert history for."}},
            "required": ["indicator"],
        },
        handler=search_alert_history,
    ),
    ToolSpec(
        name="map_mitre_technique",
        description="Match the alert's narrative text against known MITRE ATT&CK technique keywords and get recommended response actions.",
        parameters={
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Free-text alert description or raw log excerpt."}},
            "required": ["text"],
        },
        handler=map_mitre_technique,
    ),
    ToolSpec(
        name="calculate_risk_score",
        description=(
            "Combine gathered signals into a 0-100 risk score and band. Call this only after gathering "
            "reputation, asset, and technique context. Signals: any_known_malicious (bool), "
            "max_confidence (str: none/low/medium/high), asset_criticality (str), "
            "recurring_true_positive (bool), seen_before_as_benign_only (bool), technique_matched (bool)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "signals": {
                    "type": "object",
                    "description": "Aggregated boolean/string signals gathered from the other tools.",
                }
            },
            "required": ["signals"],
        },
        handler=calculate_risk_score,
    ),
]

TOOL_REGISTRY: dict[str, ToolSpec] = {spec.name: spec for spec in TOOL_SPECS}


def get_tool(name: str) -> ToolSpec:
    try:
        return TOOL_REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f"Unknown tool: {name!r}") from exc


def call_tool(name: str, tool_input: dict) -> dict:
    """Invoke a registered tool by name with its input dict, returning its output dict."""
    return get_tool(name).handler(**tool_input)


def anthropic_tool_schemas() -> list[dict]:
    """Anthropic ``tools=`` payload for every registered investigation tool."""
    return [spec.to_anthropic_schema() for spec in TOOL_SPECS]
