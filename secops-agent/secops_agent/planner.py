"""Planners decide the agent's next move: call a tool, or answer.

Two implementations share one interface (:class:`Planner`):

- :class:`OfflinePlanner` — a deterministic, fully offline strategy. It
  extracts entities (IPs, hostnames, ATT&CK IDs) from the query with regexes
  and from tool observations (e.g. IPs surfaced by a log search), then walks
  a fixed investigation checklist. No network access, no API key, fully
  reproducible — this is what the test suite and the CLI run by default.
- :class:`AnthropicPlanner` — a real multi-turn tool-use loop against the
  Claude API. The model sees the tool schemas and results and decides for
  itself which tools to call and when it has enough evidence to answer,
  which is what makes this agentic rather than a fixed pipeline.

Both plug into the same orchestration loop in :mod:`secops_agent.agent`.
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .state import InvestigationState
from .tools import IP_RE, TOOL_SCHEMAS

DEFAULT_MODEL = "claude-sonnet-5"

TECHNIQUE_RE = re.compile(r"\bT\d{4}\b", re.IGNORECASE)
HOSTNAME_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9]*(?:-[a-zA-Z0-9]+)+\b")

SYSTEM_PROMPT = (
    "You are an autonomous SOC investigation agent. You have four read-only tools: "
    "search_logs (searches the log file already bound to this investigation), "
    "lookup_ioc, lookup_mitre_technique, and check_asset_criticality. Gather evidence "
    "before answering, and use what you learn from one call to decide the next — for "
    "example, an IP address surfaced by a log search should usually be checked with "
    "lookup_ioc. Do not fabricate data: every specific IP, hostname, or verdict in your "
    "final answer must be traceable to a tool result you actually retrieved. When you "
    "have enough evidence, stop calling tools and reply with a concise incident summary: "
    "what happened, whether any indicators are confirmed malicious, which assets are "
    "affected and how critical they are, and 2-4 concrete next steps for the analyst."
)


@dataclass
class Action:
    kind: str  # "tool_call" | "final"
    tool_name: str | None = None
    tool_args: dict | None = None
    final_text: str | None = None
    tool_use_id: str | None = None  # opaque handle a stateful planner may need in observe()


class Planner(ABC):
    @abstractmethod
    def decide(self, state: InvestigationState) -> Action:
        """Return the next action given everything gathered so far."""

    def observe(self, action: Action, output: dict) -> None:
        """Optional hook for stateful planners to record a tool's output."""


class OfflinePlanner(Planner):
    """Deterministic, network-free planner used for tests, demos, and the CLI default."""

    _FALLBACK_PATTERNS = [
        "failed password",
        "invalid user",
        "authentication failure",
        "accepted password",
    ]

    def decide(self, state: InvestigationState) -> Action:
        query = state.query

        if not state.called("search_logs"):
            return Action(kind="tool_call", tool_name="search_logs", tool_args={"pattern": self._search_pattern(query)})

        ips = set(IP_RE.findall(query))
        for result in state.results_for("search_logs"):
            ips.update(result.get("extracted_ips", []))
        pending_ips = sorted(ips - state.arguments_for("lookup_ioc", "indicator"))
        if pending_ips:
            return Action(kind="tool_call", tool_name="lookup_ioc", tool_args={"indicator": pending_ips[0]})

        hostnames = [h for h in HOSTNAME_RE.findall(query) if not IP_RE.fullmatch(h)]
        pending_hosts = [h for h in hostnames if h not in state.arguments_for("check_asset_criticality", "hostname")]
        if pending_hosts:
            return Action(kind="tool_call", tool_name="check_asset_criticality", tool_args={"hostname": pending_hosts[0]})

        techniques = [m.upper() for m in TECHNIQUE_RE.findall(query)]
        pending_techniques = [t for t in techniques if t not in state.arguments_for("lookup_mitre_technique", "technique_id")]
        if pending_techniques:
            return Action(kind="tool_call", tool_name="lookup_mitre_technique", tool_args={"technique_id": pending_techniques[0]})

        return Action(kind="final", final_text=self._synthesize(state))

    def _search_pattern(self, query: str) -> str:
        lowered = query.lower()
        for candidate in self._FALLBACK_PATTERNS:
            if candidate in lowered:
                return candidate
        ips = IP_RE.findall(query)
        if ips:
            return ips[0]
        return self._FALLBACK_PATTERNS[0]

    @staticmethod
    def _synthesize(state: InvestigationState) -> str:
        lines = ["[offline deterministic planner — set ANTHROPIC_API_KEY to use the live agentic planner]"]

        log_results = state.results_for("search_logs")
        if log_results and log_results[0].get("searched"):
            r = log_results[0]
            lines.append(f"Log search for '{r['pattern']}' found {r['match_count']} matching line(s).")
            if r.get("extracted_ips"):
                lines.append(f"IPs observed in matching lines: {', '.join(r['extracted_ips'])}.")
        elif log_results:
            lines.append(f"Log search skipped: {log_results[0].get('reason', 'no log file bound')}.")

        ioc_hits = [r for r in state.results_for("lookup_ioc") if r.get("is_known_malicious")]
        ioc_clean = [r for r in state.results_for("lookup_ioc") if not r.get("is_known_malicious")]
        if ioc_hits:
            named = ", ".join(f"{h['indicator']} ({h.get('confidence', 'unknown')} confidence)" for h in ioc_hits)
            lines.append(f"KNOWN MALICIOUS indicators: {named}.")
        if ioc_clean:
            lines.append(f"No threat-intel match for: {', '.join(r['indicator'] for r in ioc_clean)}.")

        assets = [r for r in state.results_for("check_asset_criticality") if r.get("found")]
        if assets:
            for a in assets:
                lines.append(f"Asset {a['hostname']}: criticality={a['criticality']}, owner={a['owner']}, env={a['environment']}.")

        techniques = [r for r in state.results_for("lookup_mitre_technique") if r.get("found")]
        if techniques:
            for t in techniques:
                lines.append(f"ATT&CK context: {t['id']} {t['name']} ({t['tactic']}).")

        if ioc_hits:
            lines.append(
                "Recommended next steps: contain/isolate any host communicating with the flagged "
                "indicator(s), pivot on those indicators across EDR/SIEM for related activity, and "
                "escalate immediately if a critical or high-criticality asset is in scope."
            )
        else:
            lines.append(
                "Recommended next steps: no confirmed-malicious indicators from local threat intel — "
                "treat as inconclusive rather than benign, and escalate to a human analyst for manual "
                "review before closing, especially if a critical asset is involved."
            )
        return " ".join(lines)


class AnthropicPlanner(Planner):
    """Live multi-turn tool-use loop against the Claude API.

    Accepts an injected ``client`` (any object exposing
    ``.messages.create(model=..., system=..., tools=..., messages=...)`` and
    returning an object with ``.content`` and ``.stop_reason``) so the loop
    itself is unit-testable without real network access or an API key.
    """

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL, client: Any = None):
        self.model = model
        if client is not None:
            self._client = client
        else:
            api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise RuntimeError("AnthropicPlanner requires ANTHROPIC_API_KEY (or an injected client).")
            import anthropic  # type: ignore

            self._client = anthropic.Anthropic(api_key=api_key)

        self._messages: list[dict] = []
        self._pending_tool_uses: list[Any] = []
        self._pending_tool_results: list[dict] = []
        self._initialized = False

    def decide(self, state: InvestigationState) -> Action:
        if not self._initialized:
            self._messages.append(
                {
                    "role": "user",
                    "content": f"Investigate the following: {state.query}\n\n"
                    "Use the available tools to gather evidence before concluding.",
                }
            )
            self._initialized = True

        if not self._pending_tool_uses:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=self._messages,
            )
            self._messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "tool_use":
                self._pending_tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
            else:
                final_text = "".join(
                    getattr(b, "text", "") for b in response.content if getattr(b, "type", None) == "text"
                ).strip()
                return Action(kind="final", final_text=final_text or "(model returned no text content)")

        block = self._pending_tool_uses.pop(0)
        return Action(
            kind="tool_call",
            tool_name=block.name,
            tool_args=dict(block.input),
            tool_use_id=block.id,
        )

    def observe(self, action: Action, output: dict) -> None:
        self._pending_tool_results.append(
            {"type": "tool_result", "tool_use_id": action.tool_use_id, "content": json.dumps(output)}
        )
        if not self._pending_tool_uses:
            self._messages.append({"role": "user", "content": self._pending_tool_results})
            self._pending_tool_results = []
