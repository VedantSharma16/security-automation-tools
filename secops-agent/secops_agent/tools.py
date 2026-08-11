"""Tool implementations exposed to the SecOps agent, plus a sandboxed registry.

Every tool here is **read-only and local**: lookups against small JSON
datasets shipped in ``data/``, and a search over a single, pre-approved log
file. There is no live network I/O, no filesystem write, and no shell
execution — deliberately, since these tools may be invoked autonomously by
an LLM. The registry also enforces an allowlist, so a planner can never
call anything beyond the four tools defined here, and ``search_logs`` is
bound to whatever path the investigation was started with rather than
accepting an arbitrary path from the model, which would otherwise let a
prompt-injected agent read arbitrary files on disk.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "search_logs",
        "description": (
            "Search the log file bound to this investigation for lines containing a "
            "substring (case-insensitive) — e.g. an IP address, a username, or 'Failed "
            "password'. Returns matching lines and any IPv4 addresses found within them."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Substring to search for."},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "lookup_ioc",
        "description": (
            "Look up an indicator of compromise (IPv4 address, domain, or file hash) "
            "against the local threat-intel feed. Returns whether it is known malicious "
            "and, if so, confidence and notes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The IOC value to look up."},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "lookup_mitre_technique",
        "description": (
            "Look up a MITRE ATT&CK technique ID (e.g. 'T1110') for its name, tactic, "
            "and description."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "e.g. 'T1110'."},
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "check_asset_criticality",
        "description": (
            "Look up a hostname in the asset inventory for its criticality tier, owner, "
            "and environment, to help scope incident severity and escalation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "e.g. 'db-prod-01'."},
            },
            "required": ["hostname"],
        },
    },
]

ALLOWED_TOOLS = frozenset(t["name"] for t in TOOL_SCHEMAS)


class ToolError(Exception):
    """Raised when a tool is invoked that is not in the allowlist."""


def _load_json(filename: str) -> dict:
    return json.loads((DATA_DIR / filename).read_text(encoding="utf-8"))


def lookup_ioc(indicator: str) -> dict:
    needle = indicator.strip().lower()
    for entry in _load_json("threat_intel.json")["indicators"]:
        if entry["value"].lower() == needle:
            hit = {k: v for k, v in entry.items() if k != "value"}
            return {"indicator": indicator, "is_known_malicious": True, **hit}
    return {
        "indicator": indicator,
        "is_known_malicious": False,
        "notes": "No match in local threat-intel feed.",
    }


def lookup_mitre_technique(technique_id: str) -> dict:
    needle = technique_id.strip().upper()
    for technique in _load_json("mitre_attack_techniques.json")["techniques"]:
        if technique["id"] == needle:
            return {"found": True, **technique}
    return {
        "found": False,
        "technique_id": technique_id,
        "notes": "Technique ID not present in the local ATT&CK subset.",
    }


def check_asset_criticality(hostname: str) -> dict:
    needle = hostname.strip().lower()
    for asset in _load_json("asset_inventory.json")["assets"]:
        if asset["hostname"].lower() == needle:
            return {"found": True, **asset}
    return {
        "found": False,
        "hostname": hostname,
        "notes": "Host not present in asset inventory; treat criticality as unknown.",
    }


class ToolRegistry:
    """Executes tool calls by name, enforcing the allowlist and the log-path sandbox."""

    def __init__(self, log_path: str | Path | None = None, max_matches: int = 25):
        self.log_path = Path(log_path) if log_path else None
        self.max_matches = max_matches
        self._handlers: dict[str, Callable[..., dict]] = {
            "search_logs": self._search_logs,
            "lookup_ioc": lambda indicator: lookup_ioc(indicator),
            "lookup_mitre_technique": lambda technique_id: lookup_mitre_technique(technique_id),
            "check_asset_criticality": lambda hostname: check_asset_criticality(hostname),
        }

    def _search_logs(self, pattern: str) -> dict:
        if self.log_path is None:
            return {"searched": False, "reason": "No log file bound to this investigation.", "matches": []}
        if not self.log_path.is_file():
            return {"searched": False, "reason": f"Log file not found: {self.log_path}", "matches": []}

        needle = pattern.strip().lower()
        matches: list[dict] = []
        with self.log_path.open("r", encoding="utf-8", errors="replace") as handle:
            for lineno, line in enumerate(handle, start=1):
                if needle in line.lower():
                    matches.append({"line": lineno, "text": line.rstrip("\n")})
                    if len(matches) >= self.max_matches:
                        break

        extracted_ips = sorted(set(IP_RE.findall("\n".join(m["text"] for m in matches))))
        return {
            "searched": True,
            "log_path": str(self.log_path),
            "pattern": pattern,
            "match_count": len(matches),
            "matches": matches,
            "extracted_ips": extracted_ips,
        }

    def execute(self, name: str, arguments: dict) -> dict:
        if name not in ALLOWED_TOOLS:
            raise ToolError(f"Tool '{name}' is not in the allowlist: {sorted(ALLOWED_TOOLS)}")
        handler = self._handlers[name]
        try:
            result = handler(**(arguments or {}))
            return {"ok": True, "tool": name, "result": result}
        except TypeError as exc:
            return {"ok": False, "tool": name, "error": f"invalid arguments for {name}: {exc}"}
        except Exception as exc:  # defensive: a tool must never crash the agent loop
            return {"ok": False, "tool": name, "error": str(exc)}
