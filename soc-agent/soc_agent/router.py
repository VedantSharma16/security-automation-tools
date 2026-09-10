"""Decide which specialist tool(s) apply to a blob of freeform incident evidence.

An analyst rarely hands a SOC agent perfectly labeled input -- they paste
whatever they have (a log excerpt, a SIEM alert, both, or neither). Routing
that text to the right specialist tool is the actual "agentic" decision this
project makes, so it is deliberately kept out of any single tool and treated
as its own reasoning step, with two interchangeable strategies:

* ``HeuristicRouter`` -- deterministic regex signal-matching. No network, no
  API key, always available; this is what tests and CI run against.
* ``LLMRouter`` -- asks Claude to make the same run_log_triage/run_ioc_triage
  decision via tool-calling, and falls back to the heuristic router if no
  API key/package is available or the call fails.

Deciding to scan *live host processes* is never made from text heuristics or
an LLM guess -- that's a deliberately human-gated action (``--scan-processes``
on the CLI), since it inspects the actual machine the agent runs on rather
than analyzing text handed to it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

DEFAULT_MODEL = "claude-sonnet-5"

_AUTH_LOG_PATTERNS = [
    re.compile(r"\bsshd\[\d+\]"),
    re.compile(r"\bFailed password\b"),
    re.compile(r"\bAccepted (password|publickey)\b"),
    re.compile(r"\bsudo:\s"),
    re.compile(r"\buseradd\[\d+\]"),
    re.compile(r"\bcrontab\[\d+\]"),
    # BSD syslog timestamp at the start of a line, e.g. "Jan 10 03:22:10 host proc:"
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:", re.MULTILINE),
]

_ALERT_KEYWORD_PATTERN = re.compile(
    r"\b(sysmon|edr|c2|beacon|malware|phishing|mitre|att&ck|siem|ioc|iocs|"
    r"threat intel|ransomware|ttp|cve-\d{4}-\d{4,7})\b",
    re.IGNORECASE,
)
_DEFANGED_PATTERN = re.compile(r"\[\.\]|hxxps?://", re.IGNORECASE)
_HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

ROUTABLE_TOOLS = ("log_triage", "ioc_triage")


@dataclass
class RouterDecision:
    run_log_triage: bool
    run_ioc_triage: bool
    reasoning: list[str] = field(default_factory=list)
    mode: str = "heuristic"

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "run_log_triage": self.run_log_triage,
            "run_ioc_triage": self.run_ioc_triage,
            "reasoning": self.reasoning,
        }


def _detect_signals(evidence_text: str) -> tuple[bool, bool]:
    has_auth_signal = any(pattern.search(evidence_text) for pattern in _AUTH_LOG_PATTERNS)
    has_alert_signal = bool(
        _ALERT_KEYWORD_PATTERN.search(evidence_text)
        or _DEFANGED_PATTERN.search(evidence_text)
        or _HASH_PATTERN.search(evidence_text)
    )
    return has_auth_signal, has_alert_signal


class HeuristicRouter:
    """Deterministic, offline, always-available routing strategy."""

    def route(self, evidence_text: str) -> RouterDecision:
        has_auth_signal, has_alert_signal = _detect_signals(evidence_text)
        reasoning = []

        run_log = has_auth_signal
        run_ioc = has_alert_signal

        if has_auth_signal:
            reasoning.append(
                "detected auth-log style syntax (syslog timestamps / sshd / sudo / "
                "useradd / crontab entries) -> routing to log_triage"
            )
        if has_alert_signal:
            reasoning.append(
                "detected alert/IOC language (defanged indicators, hashes, or "
                "security-alert keywords) -> routing to ioc_triage"
            )
        if not has_auth_signal and not has_alert_signal:
            run_ioc = True
            reasoning.append(
                "no strong auth-log or alert signal found; running ioc_triage as a "
                "generalist fallback extractor and skipping log_triage"
            )

        return RouterDecision(run_log_triage=run_log, run_ioc_triage=run_ioc, reasoning=reasoning, mode="heuristic")


_ROUTE_TOOL_SCHEMA = {
    "name": "route_evidence",
    "description": "Decide which specialist security-triage tools should analyze this evidence.",
    "input_schema": {
        "type": "object",
        "properties": {
            "run_log_triage": {
                "type": "boolean",
                "description": "True if the evidence contains auth/syslog-style log lines (ssh, sudo, cron, user management).",
            },
            "run_ioc_triage": {
                "type": "boolean",
                "description": "True if the evidence contains alert/report text with indicators of compromise (IPs, domains, hashes, ATT&CK language).",
            },
            "reasoning": {
                "type": "string",
                "description": "One or two sentences explaining the routing decision.",
            },
        },
        "required": ["run_log_triage", "run_ioc_triage", "reasoning"],
    },
}

_SYSTEM_PROMPT = (
    "You are the routing component of a SOC triage agent. You are given a blob "
    "of freeform incident evidence and must decide which specialist tools should "
    "process it: log_triage (parses auth/syslog-style log lines for intrusion "
    "patterns) and ioc_triage (extracts indicators of compromise from alert/report "
    "text). You may select one, both, or -- only if the text is truly unrelated to "
    "either -- neither. Call the route_evidence tool with your decision; do not "
    "run either tool yourself and do not comment on live host processes, which "
    "this agent never routes automatically."
)


class LLMRouter:
    """Uses Claude tool-calling to make the routing decision, with an offline fallback."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        if self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None
        self._fallback = HeuristicRouter()

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def route(self, evidence_text: str) -> RouterDecision:
        if self._client is None:
            decision = self._fallback.route(evidence_text)
            decision.reasoning.insert(0, "LLM router unavailable (no API key or 'anthropic' package); using heuristic router")
            return decision

        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=300,
                system=_SYSTEM_PROMPT,
                tools=[_ROUTE_TOOL_SCHEMA],
                tool_choice={"type": "tool", "name": "route_evidence"},
                messages=[{"role": "user", "content": evidence_text}],
            )
            tool_use = next(block for block in response.content if getattr(block, "type", "") == "tool_use")
            decision_input = tool_use.input
            return RouterDecision(
                run_log_triage=bool(decision_input["run_log_triage"]),
                run_ioc_triage=bool(decision_input["run_ioc_triage"]),
                reasoning=[decision_input.get("reasoning", "").strip() or "(no reasoning provided)"],
                mode="llm",
            )
        except Exception as exc:  # pragma: no cover - network/SDK failure path
            decision = self._fallback.route(evidence_text)
            decision.reasoning.insert(0, f"LLM router call failed ({exc}); fell back to heuristic router")
            return decision


def get_router(use_llm: bool, model: str = DEFAULT_MODEL) -> HeuristicRouter | LLMRouter:
    return LLMRouter(model=model) if use_llm else HeuristicRouter()
