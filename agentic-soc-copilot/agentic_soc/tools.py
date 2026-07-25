"""Tool definitions the SOC agent can call while investigating an alert.

Each tool wraps a small local dataset (threat intel, known LOLBins, a MITRE
ATT&CK subset, and an asset inventory) behind a uniform interface that both
the live LLM agent (as native Anthropic tool-use schemas) and the offline
deterministic planner can call identically. Keeping the interface identical
across both is what lets the two planners share one code path for "ask a
tool a question, get structured data back."
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{2,}")
_STOPWORDS = {
    "the", "and", "or", "to", "of", "in", "on", "for", "with", "as", "by",
    "is", "are", "may", "an", "a", "that", "this", "such", "into", "was",
    "be", "their", "at", "from", "via", "over", "same", "used", "using",
}


def _tokenize(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text) if t.lower() not in _STOPWORDS}


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


@dataclass
class ToolResult:
    ok: bool
    data: dict


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    handler: Callable[[dict], ToolResult]

    def anthropic_schema(self) -> dict:
        return {"name": self.name, "description": self.description, "input_schema": self.parameters}

    def run(self, tool_input: dict) -> ToolResult:
        return self.handler(tool_input)


class ToolRegistry:
    """Loads local reference data and exposes it as callable investigation tools."""

    def __init__(self, threat_intel: dict, lolbins: dict, attack_techniques: dict, asset_inventory: dict):
        self._threat_intel = {i["value"].lower(): i for i in threat_intel.get("indicators", [])}
        self._lolbins = {b["name"].lower(): b for b in lolbins.get("binaries", [])}
        self._attack_techniques = attack_techniques.get("techniques", [])
        self._technique_tokens = [
            _tokenize(f"{t['name']} {t['text']}") for t in self._attack_techniques
        ]
        self._asset_inventory = {a["hostname"].lower(): a for a in asset_inventory.get("assets", [])}

    @classmethod
    def from_files(cls, data_dir: Path | str = DEFAULT_DATA_DIR) -> "ToolRegistry":
        data_dir = Path(data_dir)
        return cls(
            threat_intel=_load_json(data_dir / "threat_intel.json"),
            lolbins=_load_json(data_dir / "lolbins.json"),
            attack_techniques=_load_json(data_dir / "attack_techniques.json"),
            asset_inventory=_load_json(data_dir / "asset_inventory.json"),
        )

    # -- individual lookups, callable directly by the offline planner --------

    def lookup_ioc(self, indicator: str) -> dict:
        key = str(indicator).strip().lower()
        hit = self._threat_intel.get(key)
        if hit:
            return {"indicator": indicator, "matched": True, **hit}
        return {"indicator": indicator, "matched": False, "notes": "No match in local threat-intel feed."}

    def check_process(self, process_name: str) -> dict:
        key = str(process_name).strip().lower()
        hit = self._lolbins.get(key)
        if hit:
            return {"process": process_name, "known_lolbin": True, **hit}
        return {
            "process": process_name,
            "known_lolbin": False,
            "notes": "Not a recognized Living-Off-the-Land binary in the local reference list.",
        }

    def lookup_attack_technique(self, query: str, top_k: int = 2) -> dict:
        query_tokens = _tokenize(query)
        scored = []
        for technique, tokens in zip(self._attack_techniques, self._technique_tokens):
            overlap = query_tokens & tokens
            score = len(overlap) / max(1, len(tokens))
            if overlap:
                scored.append((score, technique))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        matches = [{**technique, "relevance": round(score, 3)} for score, technique in scored[:top_k]]
        return {"query": query, "matches": matches}

    def get_asset_criticality(self, hostname: str) -> dict:
        key = str(hostname).strip().lower()
        hit = self._asset_inventory.get(key)
        if hit:
            return {"hostname": hostname, "known_asset": True, **hit}
        return {
            "hostname": hostname,
            "known_asset": False,
            "criticality": "unknown",
            "notes": "Host not found in the local asset inventory; treat criticality as unknown, not low.",
        }

    # -- Tool objects, for the live tool-calling agent ------------------------

    def tools(self) -> list[Tool]:
        return [
            Tool(
                name="lookup_ioc",
                description=(
                    "Check a single indicator of compromise (IPv4 address, domain, or file hash) "
                    "against the local threat-intel feed."
                ),
                parameters={
                    "type": "object",
                    "properties": {"indicator": {"type": "string", "description": "The IOC value to look up."}},
                    "required": ["indicator"],
                },
                handler=lambda inp: ToolResult(True, self.lookup_ioc(inp["indicator"])),
            ),
            Tool(
                name="check_process",
                description=(
                    "Check whether a process/binary name is a known Living-Off-the-Land Binary "
                    "(LOLBin) commonly abused for execution, evasion, or persistence."
                ),
                parameters={
                    "type": "object",
                    "properties": {"process_name": {"type": "string", "description": "e.g. 'powershell.exe'"}},
                    "required": ["process_name"],
                },
                handler=lambda inp: ToolResult(True, self.check_process(inp["process_name"])),
            ),
            Tool(
                name="lookup_attack_technique",
                description=(
                    "Retrieve MITRE ATT&CK techniques whose description most closely matches a "
                    "piece of alert text, using keyword-overlap scoring against a local technique set."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Alert text or behavior to match against ATT&CK techniques."},
                        "top_k": {"type": "integer", "description": "Max techniques to return.", "default": 2},
                    },
                    "required": ["query"],
                },
                handler=lambda inp: ToolResult(True, self.lookup_attack_technique(inp["query"], inp.get("top_k", 2))),
            ),
            Tool(
                name="get_asset_criticality",
                description=(
                    "Look up the business criticality and role of a hostname in the asset inventory "
                    "(e.g. domain controller vs. lobby kiosk), to weigh blast radius."
                ),
                parameters={
                    "type": "object",
                    "properties": {"hostname": {"type": "string", "description": "The affected host's name."}},
                    "required": ["hostname"],
                },
                handler=lambda inp: ToolResult(True, self.get_asset_criticality(inp["hostname"])),
            ),
        ]
