"""Plan-act-observe reconnaissance agent.

Unlike a fixed pipeline, the agent re-decides its next action after every
tool call, given everything observed so far: it can skip remaining tools,
stop early, or (in live LLM mode) let the model choose the next tool from a
registry instead of following a hardcoded order. This is the "agentic
pipeline" counterpart to the RAG approach used in ioc-triage-assistant and
the rule-engine approach used in log-triage-assistant / process_threat_hunter.

Two planning modes:
  * Offline (default, no API key): a deterministic policy function chooses
    the next tool. It still branches on observations (e.g. it will not
    port-scan or fetch a TLS cert for a host that failed to resolve), so
    it is a real control loop, not just a straight line.
  * Live (``ANTHROPIC_API_KEY`` set): an LLM is given the tool registry and
    the results gathered so far and asked to pick the next action as
    strict JSON. Falls back to the offline policy if the response can't be
    parsed or the call fails, so the agent never gets stuck.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from recon_agent.dns_recon import enumerate_subdomains, resolve_host
from recon_agent.http_recon import fetch_headers, fetch_tls_certificate
from recon_agent.port_scan import COMMON_PORTS, scan_ports
from recon_agent.subdomain_takeover import scan_for_takeover

DEFAULT_MODEL = "claude-sonnet-5"

TOOL_REGISTRY: dict[str, str] = {
    "dns_lookup": "Resolve the target hostname to an IPv4 address.",
    "subdomain_enum": "Brute-force a small wordlist of common subdomain labels against the target's DNS.",
    "subdomain_takeover_scan": "Check discovered subdomains' CNAME records against known dangling-CNAME takeover fingerprints (GitHub Pages, S3, Heroku, ...).",
    "port_scan": "TCP connect-scan common ports on the resolved host and grab banners.",
    "http_headers": "Fetch HTTP(S) response headers from the target and audit security headers.",
    "tls_cert": "Fetch and inspect the target's TLS certificate (expiry, issuer).",
}

FINISH = "finish"

PLANNER_SYSTEM_PROMPT = (
    "You are a reconnaissance planning agent supporting an AUTHORIZED security "
    "assessment. You may only choose from the provided tool registry; every tool "
    "is read-only (DNS lookups, CNAME fingerprint checks, a TCP connect-scan, and "
    "standard HTTP/TLS requests) - none of them modify or exploit the target. Given the target and "
    "the results gathered so far, respond with ONLY strict JSON of the form "
    '{"action": "<tool_name or \\"finish\\">", "reason": "<one sentence>"}. '
    "Never choose a tool already present in the results. Choose \"finish\" once "
    "DNS has failed to resolve, or once enough tools have run to characterize "
    "the target's exposed attack surface."
)


@dataclass
class StepResult:
    tool: str
    data: dict


@dataclass
class ReconSession:
    target: str
    steps: list[StepResult] = field(default_factory=list)

    def record(self, tool: str, data: dict) -> None:
        self.steps.append(StepResult(tool=tool, data=data))

    def get(self, tool: str) -> dict | None:
        for step in self.steps:
            if step.tool == tool:
                return step.data
        return None

    def ran(self) -> set[str]:
        return {step.tool for step in self.steps}


def _default_policy(session: ReconSession, allow_subdomain_enum: bool) -> str | None:
    """Deterministic offline planner: a sensible order that branches on observations."""
    ran = session.ran()

    if "dns_lookup" not in ran:
        return "dns_lookup"

    dns = session.get("dns_lookup")
    if not dns or not dns.get("resolved"):
        return None  # can't do IP/host-based recon against a name that doesn't resolve

    if allow_subdomain_enum and "subdomain_enum" not in ran:
        return "subdomain_enum"
    if allow_subdomain_enum and "subdomain_enum" in ran and "subdomain_takeover_scan" not in ran:
        subdomains = session.get("subdomain_enum")
        if subdomains and subdomains.get("count", 0) > 0:
            return "subdomain_takeover_scan"
    if "port_scan" not in ran:
        return "port_scan"
    if "http_headers" not in ran:
        return "http_headers"
    if "tls_cert" not in ran:
        return "tls_cert"
    return None


class Planner:
    """Wraps LLM-driven next-action selection with the offline fallback policy."""

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

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def next_action(self, session: ReconSession, allow_subdomain_enum: bool) -> tuple[str | None, str]:
        fallback = _default_policy(session, allow_subdomain_enum)
        if self._client is None:
            return fallback, "offline deterministic policy"

        available = {k: v for k, v in TOOL_REGISTRY.items() if k not in session.ran()}
        if not allow_subdomain_enum:
            available.pop("subdomain_enum", None)

        prompt = json.dumps(
            {
                "target": session.target,
                "available_tools": available,
                "results_so_far": {step.tool: step.data for step in session.steps},
            },
            default=str,
        )
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=200,
                system=PLANNER_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text").strip()
            parsed = json.loads(text)
            action = parsed.get("action")
            reason = parsed.get("reason", "")
            if action == FINISH:
                return None, reason or "planner selected finish"
            if action in available:
                return action, reason or "planner selected tool"
            return fallback, f"planner returned unusable action {action!r}, used offline fallback"
        except Exception as exc:  # pragma: no cover - network/SDK failure path
            return fallback, f"planner call failed ({exc}), used offline fallback"


def _execute(
    tool: str,
    session: ReconSession,
    *,
    timeout: float,
    wordlist: list[str],
    ports: list[int],
    subdomain_limit: int | None,
) -> dict:
    if tool == "dns_lookup":
        result = resolve_host(session.target)
        return result.to_dict()

    if tool == "subdomain_enum":
        results = enumerate_subdomains(session.target, wordlist, limit=subdomain_limit)
        return {"found": [r.to_dict() for r in results], "count": len(results)}

    if tool == "subdomain_takeover_scan":
        subdomains = session.get("subdomain_enum")
        names = [entry["subdomain"] for entry in subdomains["found"]] if subdomains else []
        results = scan_for_takeover(names, timeout=timeout)
        return {"checked": len(names), "flagged": [r.to_dict() for r in results]}

    if tool == "port_scan":
        ip = session.get("dns_lookup")["ip"]
        results = scan_ports(ip, ports=ports, timeout=timeout)
        return {"ip": ip, "open_ports": [r.to_dict() for r in results]}

    if tool == "http_headers":
        result = fetch_headers(f"https://{session.target}/", timeout=timeout)
        if result.error:
            result = fetch_headers(f"http://{session.target}/", timeout=timeout)
        return result.to_dict()

    if tool == "tls_cert":
        result = fetch_tls_certificate(session.target, timeout=timeout)
        return result.to_dict()

    raise ValueError(f"Unknown tool: {tool}")  # pragma: no cover - guarded by TOOL_REGISTRY membership


@dataclass
class ReconRun:
    session: ReconSession
    trace: list[dict]
    planner_live: bool


def run_recon(
    target: str,
    *,
    allow_subdomain_enum: bool = True,
    wordlist: list[str] | None = None,
    ports: list[int] = COMMON_PORTS,
    subdomain_limit: int | None = None,
    timeout: float = 3.0,
    max_steps: int = len(TOOL_REGISTRY),
    planner: Planner | None = None,
) -> ReconRun:
    """Run the plan-act-observe loop against `target` and return the full trace."""
    session = ReconSession(target=target)
    planner = planner or Planner()
    wordlist = wordlist or []
    trace: list[dict] = []

    for _ in range(max_steps):
        action, reason = planner.next_action(session, allow_subdomain_enum)
        if action is None:
            trace.append({"action": "finish", "reason": reason})
            break
        data = _execute(action, session, timeout=timeout, wordlist=wordlist, ports=ports, subdomain_limit=subdomain_limit)
        session.record(action, data)
        trace.append({"action": action, "reason": reason})

    return ReconRun(session=session, trace=trace, planner_live=planner.is_live)
