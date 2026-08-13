"""The agentic recon loop.

The agent keeps a mutable `RunState` (target, open ports, fingerprints, TLS
info, vulnerability matches) and repeatedly asks a *planner*: "given what we
know so far, what's the next best action?" A planner is anything with a
`next_action(state) -> Action | None` method; returning `None` ends the run.

Two planners implement that protocol:

- `DeterministicPlanner` — a small rule-based state machine mirroring what a
  methodical analyst does by hand: scan first, fingerprint every open port,
  pull TLS certs on HTTPS ports, look up known CVEs for each identified
  service/version, then stop. Fully offline and deterministic — this is
  what the CLI uses by default and what the test suite exercises.
- `LLMPlanner` (in `llm_client.py`) — hands the *same* five tools to Claude
  via native tool-use and lets the model decide each next call itself. Used
  automatically when `ANTHROPIC_API_KEY` is set.

Both speak the same Action/Observation protocol, so `run()` doesn't need to
know or care which one is driving — that's the point of factoring the loop
this way: the tools and the run loop are policy-agnostic, only the planner
changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import tools as tools_mod
from .vuln_kb import SEVERITY_ORDER, VulnKnowledgeBase

MAX_STEPS_DEFAULT = 25


@dataclass
class Action:
    tool: str
    args: dict = field(default_factory=dict)
    reason: str = ""


@dataclass
class Observation:
    action: Action
    result: dict

    def to_dict(self) -> dict:
        return {"tool": self.action.tool, "args": self.action.args, "reason": self.action.reason, "result": self.result}


@dataclass
class RunState:
    target: str
    scanned: bool = False
    open_ports: list = field(default_factory=list)
    fingerprints: dict = field(default_factory=dict)          # port -> {service, version, source}
    fingerprinted_ports: set = field(default_factory=set)
    tls_info: dict = field(default_factory=dict)               # port -> tls_cert_info result
    tls_checked_ports: set = field(default_factory=set)
    vuln_matches: list = field(default_factory=list)           # list[VulnMatch]
    checked_vuln_ports: set = field(default_factory=set)
    transcript: list = field(default_factory=list)             # list[Observation]


@dataclass
class AgentRunResult:
    target: str
    open_ports: list
    fingerprints: dict
    tls_info: dict
    vuln_matches: list
    risk: str
    steps_taken: int
    completed: bool
    transcript: list

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "fingerprints": self.fingerprints,
            "tls_info": self.tls_info,
            "vuln_matches": [m.to_dict() for m in self.vuln_matches],
            "risk": self.risk,
            "steps_taken": self.steps_taken,
            "completed": self.completed,
            "transcript": [o.to_dict() for o in self.transcript],
        }


class DeterministicPlanner:
    """Rule-based agent policy: always the same next step for the same state."""

    def __init__(self, ports: list[int] | None = None):
        self.ports = ports

    def next_action(self, state: RunState) -> Action | None:
        if not state.scanned:
            return Action(
                "tcp_connect_scan",
                {"host": state.target, "ports": self.ports},
                "Start with a scan of common ports to see what's listening.",
            )

        for port in state.open_ports:
            if port in state.fingerprinted_ports:
                continue
            if port in tools_mod.HTTP_PORTS or port in tools_mod.TLS_HTTP_PORTS:
                use_tls = port in tools_mod.TLS_HTTP_PORTS
                return Action(
                    "http_headers",
                    {"host": state.target, "port": port, "use_tls": use_tls},
                    f"Port {port} looks like HTTP{'S' if use_tls else ''}; fetch headers to fingerprint the server.",
                )
            return Action(
                "grab_banner",
                {"host": state.target, "port": port},
                f"Port {port} is open; grab its banner to identify the service.",
            )

        for port in state.open_ports:
            if port in tools_mod.TLS_HTTP_PORTS and port not in state.tls_checked_ports:
                return Action(
                    "tls_cert_info",
                    {"host": state.target, "port": port},
                    f"Port {port} serves TLS; inspect the certificate for expiry/config issues.",
                )

        for port, fp in state.fingerprints.items():
            if port in state.checked_vuln_ports:
                continue
            if fp.get("service"):
                return Action(
                    "vuln_lookup",
                    {"service": fp["service"], "version": fp.get("version"), "port": port},
                    f"Port {port} fingerprinted as {fp['service']} {fp.get('version') or '(unknown version)'}; "
                    "check the local CVE knowledge base.",
                )

        return None


TOOL_REGISTRY = {
    "tcp_connect_scan": tools_mod.tcp_connect_scan,
    "grab_banner": tools_mod.grab_banner,
    "http_headers": tools_mod.http_headers,
    "tls_cert_info": tools_mod.tls_cert_info,
}


def _execute(action: Action, kb: VulnKnowledgeBase, tools: dict) -> dict:
    if action.tool == "vuln_lookup":
        matches = kb.lookup(action.args.get("service"), action.args.get("version"), action.args.get("port"))
        return {"matches": [m.to_dict() for m in matches]}
    if action.tool == "finish":
        return {}
    func = tools.get(action.tool)
    if func is None:
        raise ValueError(f"Unknown tool: {action.tool}")
    return func(**action.args)


def _apply(action: Action, result: dict, state: RunState, kb: VulnKnowledgeBase) -> None:
    if action.tool == "tcp_connect_scan":
        state.scanned = True
        state.open_ports = result["open_ports"]
    elif action.tool == "grab_banner":
        port = action.args["port"]
        state.fingerprinted_ports.add(port)
        if result.get("service"):
            state.fingerprints[port] = {"service": result["service"], "version": result.get("version"), "source": "banner"}
    elif action.tool == "http_headers":
        port = action.args["port"]
        state.fingerprinted_ports.add(port)
        if result.get("service"):
            state.fingerprints[port] = {"service": result["service"], "version": result.get("version"), "source": "http"}
    elif action.tool == "tls_cert_info":
        port = action.args["port"]
        state.tls_checked_ports.add(port)
        state.tls_info[port] = result
    elif action.tool == "vuln_lookup":
        port = action.args.get("port")
        state.checked_vuln_ports.add(port)
        for m in result.get("matches", []):
            from .vuln_kb import VulnMatch

            state.vuln_matches.append(VulnMatch(**m))


def _overall_risk(vuln_matches: list, open_ports: list) -> str:
    present = {m.severity for m in vuln_matches if m.severity in SEVERITY_ORDER}
    for level in SEVERITY_ORDER:
        if level in present:
            return level
    return "low" if open_ports else "none"


def run(
    target: str,
    ports: list[int] | None = None,
    planner=None,
    kb: VulnKnowledgeBase | None = None,
    max_steps: int = MAX_STEPS_DEFAULT,
    tool_overrides: dict | None = None,
) -> AgentRunResult:
    """Drive the agent loop to completion (or until `max_steps` is hit)."""
    state = RunState(target=target)
    planner = planner or DeterministicPlanner(ports=ports)
    kb = kb or VulnKnowledgeBase()
    tools = {**TOOL_REGISTRY, **(tool_overrides or {})}

    if hasattr(planner, "start"):
        planner.start(target)

    completed = False
    steps_taken = 0
    for _ in range(max_steps):
        action = planner.next_action(state)
        if action is None:
            completed = True
            break
        steps_taken += 1
        result = _execute(action, kb, tools)
        state.transcript.append(Observation(action, result))
        _apply(action, result, state, kb)
        if hasattr(planner, "observe"):
            planner.observe(result)

    risk = _overall_risk(state.vuln_matches, state.open_ports)
    return AgentRunResult(
        target=target,
        open_ports=state.open_ports,
        fingerprints=state.fingerprints,
        tls_info=state.tls_info,
        vuln_matches=state.vuln_matches,
        risk=risk,
        steps_taken=steps_taken,
        completed=completed,
        transcript=state.transcript,
    )
