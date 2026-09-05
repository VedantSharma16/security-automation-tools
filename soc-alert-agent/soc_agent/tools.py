"""The agent's investigative toolbox.

Every tool is a pure, local, offline function over the bundled demo
datasets (``data/*.json``) and the current alert queue — no live network
calls. This keeps the agent loop fully deterministic and safe to run
against the sample data, whether it's driven by the deterministic planner
or by an LLM deciding which tool to call next.

``ToolRegistry.dispatch`` is the single call path both backends use, so a
tool behaves identically regardless of who's calling it, and each tool has
one direct unit test independent of any agent loop.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Tool schemas in Anthropic Messages API tool-use format. Shared by the LLM
# agent (passed as `tools=`) and by documentation/tests that want the schema
# without importing the LLM-specific module.
TOOL_SCHEMAS = [
    {
        "name": "lookup_ioc_reputation",
        "description": (
            "Check a single indicator (IP address or domain) against the local "
            "threat-intelligence feed. Returns whether it is known malicious, "
            "at what confidence, and analyst notes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"indicator": {"type": "string", "description": "IP address or domain to look up."}},
            "required": ["indicator"],
        },
    },
    {
        "name": "get_asset_criticality",
        "description": (
            "Look up a hostname in the asset inventory / CMDB to get its business "
            "criticality tier, environment, and owning team."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string", "description": "Hostname to look up."}},
            "required": ["host"],
        },
    },
    {
        "name": "search_attack_technique",
        "description": (
            "Search a curated MITRE ATT&CK technique subset for techniques whose "
            "keywords best match the given text (e.g. an alert description). "
            "Returns the top matches ranked by keyword-overlap score."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Free text to match against technique keywords."},
                "top_k": {"type": "integer", "description": "Number of techniques to return.", "default": 3},
            },
            "required": ["query"],
        },
    },
    {
        "name": "check_related_alerts",
        "description": (
            "Search the current alert queue for other alerts sharing the same "
            "source IP, host, or user as the given alert, to detect campaign-level "
            "correlation rather than judging the alert in isolation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"alert_id": {"type": "string", "description": "The alert_id to correlate against."}},
            "required": ["alert_id"],
        },
    },
    {
        "name": "escalate",
        "description": (
            "Terminal action: escalate this alert to a human analyst / IR team as "
            "a confirmed or likely-true positive requiring action. Call this only "
            "once you have gathered enough evidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string", "description": "Evidence-grounded justification."}},
            "required": ["reason"],
        },
    },
    {
        "name": "monitor",
        "description": (
            "Terminal action: keep this alert open for passive monitoring — the "
            "evidence is inconclusive or moderate, not urgent enough to escalate "
            "and not clearly benign enough to close."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string", "description": "Evidence-grounded justification."}},
            "required": ["reason"],
        },
    },
    {
        "name": "close",
        "description": (
            "Terminal action: close this alert as benign / false positive / "
            "insufficient evidence of malicious activity. Call this only once "
            "you have gathered enough evidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string", "description": "Evidence-grounded justification."}},
            "required": ["reason"],
        },
    },
]

TERMINAL_TOOLS = {"escalate", "monitor", "close"}


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class ToolRegistry:
    """Loads the demo datasets and dispatches tool calls against them and the alert queue."""

    def __init__(
        self,
        alerts: list | None = None,
        threat_intel_path: Path | None = None,
        asset_inventory_path: Path | None = None,
        attack_techniques_path: Path | None = None,
    ):
        self.alerts = alerts or []
        self._threat_intel = _load_json(threat_intel_path or _DATA_DIR / "threat_intel.json")["indicators"]
        self._asset_inventory = _load_json(asset_inventory_path or _DATA_DIR / "asset_inventory.json")["assets"]
        self._techniques = _load_json(attack_techniques_path or _DATA_DIR / "attack_techniques.json")["techniques"]

    # -- individual tools -------------------------------------------------

    def lookup_ioc_reputation(self, indicator: str) -> dict:
        for entry in self._threat_intel:
            if entry["value"].lower() == indicator.lower():
                return {
                    "indicator": indicator,
                    "known_malicious": entry["known_malicious"],
                    "confidence": entry["confidence"],
                    "source": entry["source"],
                    "notes": entry["notes"],
                }
        return {
            "indicator": indicator,
            "known_malicious": False,
            "confidence": "unknown",
            "source": None,
            "notes": "No match in the local threat-intel feed.",
        }

    def get_asset_criticality(self, host: str) -> dict:
        for entry in self._asset_inventory:
            if entry["host"].lower() == host.lower():
                return {
                    "host": host,
                    "criticality": entry["criticality"],
                    "environment": entry["environment"],
                    "owner": entry["owner"],
                    "notes": entry["notes"],
                }
        return {
            "host": host,
            "criticality": "unknown",
            "environment": "unknown",
            "owner": None,
            "notes": "Host not found in the asset inventory.",
        }

    def search_attack_technique(self, query: str, top_k: int = 3) -> dict:
        query_tokens = _tokenize(query)
        scored = []
        for technique in self._techniques:
            matched = [kw for kw in technique["keywords"] if _tokenize(kw) <= query_tokens]
            if matched:
                scored.append(
                    {
                        "id": technique["id"],
                        "name": technique["name"],
                        "tactic": technique["tactic"],
                        "score": len(matched),
                        "matched_keywords": matched,
                    }
                )
        scored.sort(key=lambda m: m["score"], reverse=True)
        return {"query": query, "matches": scored[:top_k]}

    def check_related_alerts(self, alert_id: str) -> dict:
        target = next((a for a in self.alerts if a.get("alert_id") == alert_id), None)
        if target is None:
            return {"alert_id": alert_id, "related": [], "count": 0}

        related = []
        for other in self.alerts:
            if other.get("alert_id") == alert_id:
                continue
            shared = [
                field
                for field in ("src_ip", "host", "user")
                if target.get(field) and target.get(field) == other.get(field)
            ]
            if shared:
                related.append({"alert_id": other["alert_id"], "shared_fields": shared})
        return {"alert_id": alert_id, "related": related, "count": len(related)}

    @staticmethod
    def escalate(reason: str) -> dict:
        return {"verdict": "escalate", "reason": reason}

    @staticmethod
    def monitor(reason: str) -> dict:
        return {"verdict": "monitor", "reason": reason}

    @staticmethod
    def close(reason: str) -> dict:
        return {"verdict": "close", "reason": reason}

    # -- unified dispatch ---------------------------------------------------

    def dispatch(self, tool_name: str, tool_args: dict) -> dict:
        handlers = {
            "lookup_ioc_reputation": self.lookup_ioc_reputation,
            "get_asset_criticality": self.get_asset_criticality,
            "search_attack_technique": self.search_attack_technique,
            "check_related_alerts": self.check_related_alerts,
            "escalate": self.escalate,
            "monitor": self.monitor,
            "close": self.close,
        }
        handler = handlers.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        return handler(**tool_args)


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
