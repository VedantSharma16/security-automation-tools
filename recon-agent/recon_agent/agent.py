"""Agentic recon orchestration.

Live mode drives Claude's tool-use loop: the model decides which recon
tool to call next (DNS/subdomain enumeration, port scanning, HTTP/TLS
fingerprinting) based on the results of prior calls, until it has enough
to hand back a short analyst narrative instead of another tool call.

Without ``ANTHROPIC_API_KEY`` set (or if the ``anthropic`` package isn't
installed), :func:`run_recon` falls back to a fixed deterministic pipeline
that calls the same tool functions directly, in a fixed order. This keeps
the tool fully usable — and testable — offline, matching the pattern used
elsewhere in this repo (see ``ioc-triage-assistant/ioc_triage/llm_client.py``).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import dns_recon, http_fingerprint, port_scan
from .port_scan import DEFAULT_PORTS
from .tools import TOOL_SCHEMAS, dispatch

DEFAULT_MODEL = "claude-sonnet-5"
MAX_AGENT_TURNS = 6

SYSTEM_PROMPT = (
    "You are a reconnaissance agent supporting an authorized penetration test. "
    "Explicit written authorization to test the target has already been confirmed "
    "before this session started. Use the available tools to enumerate subdomains, "
    "scan for open ports, and fingerprint any web services found, in whatever order "
    "makes sense given results so far. Once you've called scan_ports, and called "
    "fingerprint_web_services if any web ports (80, 443, 8000, 8080, 8443) were open, "
    "stop calling tools and reply with a short plain-text summary for an analyst: what "
    "was found and what's worth investigating first."
)


@dataclass
class ReconRun:
    target: str
    ip: str | None = None
    subdomains: dict[str, str] = field(default_factory=dict)
    open_ports: list[port_scan.PortResult] = field(default_factory=list)
    http_fingerprints: list[http_fingerprint.HttpFingerprint] = field(default_factory=list)
    agent_narrative: str | None = None
    tool_calls_made: list[str] = field(default_factory=list)


def _offline_narrative(run: ReconRun) -> str:
    parts = ["[offline deterministic pipeline — set ANTHROPIC_API_KEY for an agentic run]"]
    parts.append(f"Resolved {run.target} to {run.ip or 'unresolved'}.")
    if run.subdomains:
        parts.append(f"Found {len(run.subdomains)} subdomain(s): {', '.join(sorted(run.subdomains))}.")
    else:
        parts.append("No subdomains from the built-in wordlist resolved.")
    if run.open_ports:
        ports = ", ".join(f"{p.port}/{p.service}" for p in run.open_ports)
        parts.append(f"Open ports: {ports}.")
    else:
        parts.append("No open ports found among the scanned set.")
    if run.http_fingerprints:
        parts.append(f"Fingerprinted {len(run.http_fingerprints)} web service(s).")
    return " ".join(parts)


def _deterministic_pipeline(target: str, wordlist: list[str]) -> ReconRun:
    run = ReconRun(target=target)
    run.ip = dns_recon.resolve(target)
    run.subdomains = dns_recon.enumerate_subdomains(target, wordlist)
    run.tool_calls_made.append("resolve_and_enumerate_subdomains")

    run.open_ports = port_scan.scan_ports(target, ports=DEFAULT_PORTS)
    run.tool_calls_made.append("scan_ports")

    web_ports = [p.port for p in run.open_ports if p.port in http_fingerprint.WEB_PORTS]
    if web_ports:
        run.http_fingerprints = [http_fingerprint.fingerprint_http(target, port) for port in web_ports]
        run.tool_calls_made.append("fingerprint_web_services")

    run.agent_narrative = _offline_narrative(run)
    return run


def _absorb_tool_result(run: ReconRun, name: str, result: dict) -> None:
    if name == "resolve_and_enumerate_subdomains":
        run.ip = result.get("ip")
        run.subdomains = result.get("subdomains", {})
    elif name == "scan_ports":
        run.open_ports = [port_scan.PortResult(**p) for p in result.get("open_ports", [])]
    elif name == "fingerprint_web_services":
        run.http_fingerprints = [
            http_fingerprint.HttpFingerprint(**fp) for fp in result.get("fingerprints", [])
        ]


def _fill_missing(run: ReconRun, target: str, wordlist: list[str]) -> None:
    """Best-effort completion of a run that the agent loop aborted mid-way."""
    if run.ip is None and not run.subdomains:
        run.ip = dns_recon.resolve(target)
        run.subdomains = dns_recon.enumerate_subdomains(target, wordlist)
    if not run.open_ports:
        run.open_ports = port_scan.scan_ports(target, ports=DEFAULT_PORTS)


def run_recon(
    target: str,
    *,
    wordlist: list[str],
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
) -> ReconRun:
    """Run recon against ``target``, agentically via Claude when possible."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _deterministic_pipeline(target, wordlist)

    try:
        import anthropic  # type: ignore
    except ImportError:
        return _deterministic_pipeline(target, wordlist)

    client = anthropic.Anthropic(api_key=api_key)
    run = ReconRun(target=target)
    messages: list[dict] = [{"role": "user", "content": f"Target: {target}"}]

    for _ in range(MAX_AGENT_TURNS):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=messages,
            )
        except Exception as exc:  # noqa: BLE001 - network/SDK failure mid-run
            _fill_missing(run, target, wordlist)
            run.agent_narrative = (
                _offline_narrative(run) + f"\n\n[LLM call failed mid-run, offline pipeline used to fill "
                f"remaining data: {exc}]"
            )
            return run

        messages.append({"role": "assistant", "content": response.content})
        tool_uses = [block for block in response.content if getattr(block, "type", "") == "tool_use"]

        if not tool_uses:
            text = "".join(
                block.text for block in response.content if getattr(block, "type", "") == "text"
            ).strip()
            run.agent_narrative = text or _offline_narrative(run)
            return run

        tool_results = []
        for call in tool_uses:
            run.tool_calls_made.append(call.name)
            result = dispatch(call.name, call.input, wordlist=wordlist, ports_list=DEFAULT_PORTS)
            _absorb_tool_result(run, call.name, result)
            tool_results.append(
                {"type": "tool_result", "tool_use_id": call.id, "content": json.dumps(result)}
            )
        messages.append({"role": "user", "content": tool_results})

    run.agent_narrative = _offline_narrative(run) + "\n\n[agent reached the max tool-call turn limit]"
    return run
