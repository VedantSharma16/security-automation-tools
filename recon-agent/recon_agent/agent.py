"""The agentic recon loop, with a deterministic offline fallback.

Live mode hands the Claude API a set of read-only recon tools (via the
official ``anthropic`` SDK's tool-use / function-calling support) and lets
the model decide which tools to call and in what order, looping until it
stops requesting tools or a step budget is exhausted. Without
``ANTHROPIC_API_KEY`` set, :meth:`ReconAgent.run` falls back to calling
every tool once in a fixed order, so the tool is fully runnable — and
testable — offline.

Either way, findings and severity are derived deterministically from the
raw tool output (see :mod:`recon_agent.findings`) — the LLM only supplies
the narrative summary layered on top, never the facts themselves.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from recon_agent import tools
from recon_agent.findings import Finding, derive_findings, overall_severity

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_STEPS = 6

TOOL_SPECS = [
    {
        "name": "dns_lookup",
        "description": "Resolve A/AAAA DNS records for a domain to confirm it's live and see where it's hosted.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Domain name, e.g. example.com"}},
            "required": ["domain"],
        },
    },
    {
        "name": "subdomain_enum",
        "description": "Check a small built-in wordlist of common subdomains and report which resolve publicly.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "http_probe",
        "description": (
            "Send an HTTP(S) GET request to a host and report status code, server banner, "
            "and any missing recommended security headers (HSTS, CSP, X-Frame-Options, etc.)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "use_https": {"type": "boolean", "description": "Use HTTPS. Defaults to true."},
            },
            "required": ["host"],
        },
    },
    {
        "name": "tls_probe",
        "description": "Inspect a host's TLS certificate: issuer, subject, expiry, and negotiated protocol version.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["host"],
        },
    },
    {
        "name": "whois_lookup",
        "description": "Look up public WHOIS registration data for a domain (registrar, creation/expiration dates).",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
]

TOOL_IMPL = {
    "dns_lookup": tools.dns_lookup,
    "subdomain_enum": tools.subdomain_enum,
    "http_probe": tools.http_probe,
    "tls_probe": tools.tls_probe,
    "whois_lookup": tools.whois_lookup,
}

SYSTEM_PROMPT = (
    "You are a passive-recon assistant supporting an AUTHORIZED security assessment "
    "(pentest, bug bounty, or asset-inventory review) of a target the operator is permitted "
    "to test. Investigate the given target using only the provided read-only, passive tools "
    "(DNS resolution, subdomain wordlist checks, HTTP header probing, TLS certificate "
    "inspection, WHOIS lookup). Never call a tool against a host outside the given target "
    "and its direct subdomains, and never attempt anything beyond passive information "
    "gathering. Call tools to gather evidence, then stop calling tools and write a concise "
    "attack-surface summary: what you found, why it matters, and 2-4 concrete remediation or "
    "follow-up steps. Be direct; don't pad the summary with disclaimers."
)


@dataclass
class ReconReport:
    target: str
    agent_backed: bool
    steps_taken: int
    tool_results: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    severity: str = "info"
    narrative: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "agent_backed": self.agent_backed,
            "steps_taken": self.steps_taken,
            "tool_results": self.tool_results,
            "findings": [f.to_dict() for f in self.findings],
            "severity": self.severity,
            "narrative": self.narrative,
        }


class ReconAgent:
    """Runs an agentic (or offline fallback) passive-recon pass against a target."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_steps: int = DEFAULT_MAX_STEPS,
        tool_impl: dict | None = None,
    ):
        self.model = model
        self.max_steps = max_steps
        self.tool_impl = tool_impl or TOOL_IMPL
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

    def run(self, target: str) -> ReconReport:
        if self.is_live:
            try:
                return self._run_agentic(target)
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                report = self._run_offline(target)
                report.narrative += f"\n\n[Agent run failed, offline fallback used: {exc}]"
                return report
        return self._run_offline(target)

    def _call_tool(self, name: str, tool_input: dict, tool_results: dict) -> dict:
        impl = self.tool_impl.get(name)
        if impl is None:
            result = {"error": f"unknown tool '{name}'"}
        else:
            try:
                result = impl(**tool_input)
            except Exception as exc:  # noqa: BLE001 - surfaced to the caller/model as data, not raised
                result = {"error": str(exc)}
        tool_results.setdefault(name, []).append(result)
        return result

    def _run_offline(self, target: str) -> ReconReport:
        tool_results: dict = {}
        self._call_tool("dns_lookup", {"domain": target}, tool_results)
        self._call_tool("subdomain_enum", {"domain": target}, tool_results)
        self._call_tool("http_probe", {"host": target}, tool_results)
        self._call_tool("tls_probe", {"host": target}, tool_results)
        self._call_tool("whois_lookup", {"domain": target}, tool_results)

        findings = derive_findings(tool_results)
        severity = overall_severity(findings)
        narrative = self._offline_narrative(severity, findings)
        return ReconReport(target, False, 5, tool_results, findings, severity, narrative)

    def _run_agentic(self, target: str) -> ReconReport:
        tool_results: dict = {}
        messages = [{
            "role": "user",
            "content": (
                f"Target for this authorized recon engagement: {target}\n"
                "Investigate its public attack surface using the available tools, then "
                "summarize your findings."
            ),
        }]

        narrative = ""
        steps = 0
        while steps < self.max_steps:
            steps += 1
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOL_SPECS,
                messages=messages,
            )

            tool_use_blocks = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
            text_blocks = [b.text for b in response.content if getattr(b, "type", "") == "text"]

            if not tool_use_blocks:
                narrative = "\n".join(text_blocks).strip()
                break

            messages.append({"role": "assistant", "content": response.content})
            tool_result_content = []
            for block in tool_use_blocks:
                result = self._call_tool(block.name, block.input, tool_results)
                tool_result_content.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result, default=str),
                })
            messages.append({"role": "user", "content": tool_result_content})

        findings = derive_findings(tool_results)
        severity = overall_severity(findings)
        if not narrative:
            narrative = (
                "[Reached the tool-call step budget before the model produced a final summary. "
                "Findings below are derived directly from the tool results gathered so far.]"
            )
        return ReconReport(target, True, steps, tool_results, findings, severity, narrative)

    @staticmethod
    def _offline_narrative(severity: str, findings: list[Finding]) -> str:
        parts = [
            "[offline deterministic pipeline — set ANTHROPIC_API_KEY for an adaptive agentic run]",
            f"Overall severity: {severity.upper()}.",
        ]
        if findings:
            parts.append(f"{len(findings)} finding(s) identified across DNS, subdomain, HTTP, and TLS checks.")
            for finding in findings[:3]:
                parts.append(f"- [{finding.severity}] {finding.description}")
        else:
            parts.append("No notable issues identified by the built-in heuristic checks.")
        parts.append(
            "Recommended next steps: review any exposed sensitive subdomains for unintended "
            "public access, add missing security headers, and renew or rotate certificates "
            "flagged as expiring."
        )
        return "\n".join(parts)
