"""The bounded think-act-observe loop that drives a recon pass.

A `policy` decides the next tool call given everything observed so far; the
agent executes that tool and records the result. Two policies are provided:

- `deterministic_next_action` — a fixed decision tree that always runs the
  same sequence of read-only probes for a target. This is the default,
  fully offline, and the path exercised by the test suite.
- `LLMPolicy` — delegates the "what next?" decision to an LLM via Anthropic
  tool use, so the agent can skip steps that are clearly unnecessary (e.g.
  not bothering with a TLS check after HTTPS refused the connection) or
  react to something unusual in a response. It transparently falls back to
  the deterministic policy if no API key is configured or the call fails,
  so the agent is always runnable.

Either way, the loop is capped at `max_steps` — a runaway or buggy policy
still terminates and the tool set is read-only, so the worst case is a
handful of wasted GET requests, never an unbounded or destructive scan.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable

from . import http_probe
from .models import AgentStep, Finding, ProbeResult, TLSResult
from .tls_analyzer import analyze_tls
from .tools import TOOLS, tool_schemas

DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_STEPS = 6
DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a recon agent performing passive attack-surface enumeration against a "
    "single authorized web host. You may only call the tools provided — each is a "
    "read-only probe or the security-header analyzer. Prefer the smallest sequence "
    "of calls that establishes: whether HTTPS is reachable and its header hygiene, "
    "whether an HTTP fallback exists, and whether the TLS configuration is sound. "
    "Call `finish` as soon as further probes would not add signal."
)


@dataclass
class Action:
    tool: str
    args: dict
    reason: str = ""


@dataclass
class AgentState:
    host: str
    timeout: float = DEFAULT_TIMEOUT
    steps: list[AgentStep] = field(default_factory=list)
    probes: dict[str, ProbeResult] = field(default_factory=dict)
    analyzed: set = field(default_factory=set)
    tls: TLSResult | None = None
    findings: list[Finding] = field(default_factory=list)
    done: bool = False
    # Injectable so tests and the CLI's --fixture mode can replace live
    # network calls with canned results, without touching tool dispatch.
    probe_url_fn: Callable = http_probe.probe_url
    probe_tls_fn: Callable = http_probe.probe_tls


def deterministic_next_action(state: AgentState) -> Action:
    """Fixed decision tree: HTTPS -> analyze -> (HTTP fallback if needed) -> TLS -> finish."""
    if "https" not in state.probes:
        return Action("probe_https", {"host": state.host}, "start with HTTPS, the expected default")

    https_probe = state.probes["https"]

    if https_probe.ok and "https" not in state.analyzed:
        return Action("analyze_headers", {"probe_key": "https"}, "check HTTPS response security headers")

    if not https_probe.ok and "http" not in state.probes:
        return Action("probe_http", {"host": state.host}, "HTTPS was unreachable; check for an HTTP fallback")

    if "http" in state.probes and state.probes["http"].ok and "http" not in state.analyzed:
        return Action("analyze_headers", {"probe_key": "http"}, "check HTTP fallback security headers")

    if https_probe.ok and state.tls is None:
        return Action("probe_tls", {"host": state.host}, "confirm TLS version and certificate expiry")

    findings_count = len(state.findings)
    return Action(
        "finish",
        {"summary": f"{findings_count} finding(s) across {len(state.probes)} probe(s)"},
        "no further probe would add signal",
    )


class LLMPolicy:
    """Chooses the next action via Anthropic tool use; falls back offline."""

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
        self._messages: list[dict] = []

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def __call__(self, state: AgentState) -> Action:
        if self._client is None:
            return deterministic_next_action(state)
        try:
            return self._ask_llm(state)
        except Exception:  # pragma: no cover - network/SDK failure path
            return deterministic_next_action(state)

    def _ask_llm(self, state: AgentState) -> Action:  # pragma: no cover - requires live API access
        if not self._messages:
            self._messages.append(
                {"role": "user", "content": f"Begin passive recon against host: {state.host}"}
            )
        else:
            last = state.steps[-1]
            self._messages.append({"role": "user", "content": f"Result of {last.tool}: {last.to_dict()['result']}"})

        response = self._client.messages.create(
            model=self.model,
            max_tokens=500,
            system=SYSTEM_PROMPT,
            tools=tool_schemas(),
            messages=self._messages,
        )
        self._messages.append({"role": "assistant", "content": response.content})

        for block in response.content:
            if getattr(block, "type", "") == "tool_use":
                return Action(tool=block.name, args=block.input or {}, reason="llm")
        return Action(tool="finish", args={"summary": ""}, reason="llm ended without a tool call")


def _apply_result(state: AgentState, action: Action, result) -> None:
    if action.tool == "probe_https":
        state.probes["https"] = result
    elif action.tool == "probe_http":
        state.probes["http"] = result
    elif action.tool == "probe_tls":
        state.tls = result
        state.findings.extend(analyze_tls(result))
    elif action.tool == "analyze_headers":
        state.analyzed.add(action.args["probe_key"])
        state.findings.extend(result)


class ReconAgent:
    def __init__(self, policy=None, max_steps: int = DEFAULT_MAX_STEPS):
        self.policy = policy or deterministic_next_action
        self.max_steps = max_steps

    def run(
        self,
        host: str,
        timeout: float = DEFAULT_TIMEOUT,
        probe_url_fn: Callable = http_probe.probe_url,
        probe_tls_fn: Callable = http_probe.probe_tls,
    ) -> AgentState:
        state = AgentState(host=host, timeout=timeout, probe_url_fn=probe_url_fn, probe_tls_fn=probe_tls_fn)
        for _ in range(self.max_steps):
            action = self.policy(state)
            tool = TOOLS[action.tool]
            result = tool.func(state, action.args)
            state.steps.append(AgentStep(tool=action.tool, args=action.args, result=result, note=action.reason))
            _apply_result(state, action, result)
            if action.tool == "finish":
                state.done = True
                break
        return state
