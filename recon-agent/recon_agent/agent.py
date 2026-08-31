"""The agent loop.

This is the piece that makes this project different from a fixed
extract → enrich → summarize pipeline: when a Claude API key is available,
the LLM itself decides which recon tool to call next, observes the real
result, and decides again — a genuine ReAct-style tool-calling loop, not a
canned sequence with an LLM bolted on at the end for narration.

Without an API key (or if the SDK isn't installed), :class:`ReconAgent`
falls back to a deterministic fixed plan that runs every tool once in a
sensible order. This keeps the CLI, and the test suite, fully functional
offline — the same graceful-degradation pattern used by the other tools in
this repo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .scoring import RiskAssessment, score_findings
from .tools import TOOL_SPECS, ToolRegistry

DEFAULT_MODEL = "claude-sonnet-5"
MAX_ITERATIONS_DEFAULT = 6

SYSTEM_PROMPT = (
    "You are an authorized passive-recon assistant helping a penetration "
    "tester scope a target domain before active testing begins. You may "
    "only use the provided tools, which perform passive, non-intrusive "
    "checks (DNS lookups, an HTTP GET of the homepage, a robots.txt fetch, "
    "and a TLS handshake to read the certificate) — never attempt anything "
    "beyond what the tools expose, and never suggest active exploitation. "
    "Call tools to gather what you need, reasoning from each result about "
    "what to check next (e.g. an MX record suggests checking SPF/DMARC via "
    "a TXT lookup; a fingerprinted server suggests checking its TLS config). "
    "Once you have enough information, stop calling tools and respond with "
    "a concise recon summary for the tester: infrastructure overview, "
    "concrete findings ranked by how useful they'd be in planning a test, "
    "and any hygiene issues observed (missing security headers, weak TLS, "
    "exposed paths). Be specific and reference the actual values observed."
)

# Fixed, deterministic tool sequence used when no LLM is available.
OFFLINE_PLAN: list[tuple[str, dict]] = [
    ("dns_lookup", {"record_type": "A"}),
    ("dns_lookup", {"record_type": "AAAA"}),
    ("dns_lookup", {"record_type": "MX"}),
    ("dns_lookup", {"record_type": "TXT"}),
    ("dns_lookup", {"record_type": "NS"}),
    ("http_headers", {}),
    ("robots_check", {}),
    ("tls_check", {"port": 443}),
]


@dataclass
class ToolCallTrace:
    tool: str
    arguments: dict
    result: dict


@dataclass
class ReconReport:
    target: str
    is_live: bool
    trace: list[ToolCallTrace] = field(default_factory=list)
    narrative: str = ""
    risk: "RiskAssessment | None" = None


class ReconAgent:
    """Runs the recon loop against ``target_domain`` via ``registry``."""

    def __init__(
        self,
        target_domain: str,
        registry: "ToolRegistry | None" = None,
        api_key: "str | None" = None,
        model: str = DEFAULT_MODEL,
        max_iterations: int = MAX_ITERATIONS_DEFAULT,
    ):
        self.target_domain = target_domain
        self.registry = registry or ToolRegistry(target_domain)
        self.model = model
        self.max_iterations = max_iterations
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        self._final_narrative: "str | None" = None
        if self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def run(self) -> ReconReport:
        trace = self._run_live() if self._client is not None else self._run_offline()
        report = ReconReport(target=self.target_domain, is_live=self.is_live, trace=trace)
        report.risk = score_findings(
            http_finding=self.registry.http_finding,
            robots_finding=self.registry.robots_finding,
            tls_finding=self.registry.tls_finding,
        )
        if self._client is not None:
            report.narrative = self._final_narrative or self._offline_narrative(report.risk)
        else:
            report.narrative = self._offline_narrative(report.risk)
        return report

    def _run_offline(self) -> list[ToolCallTrace]:
        trace = []
        for tool_name, arguments in OFFLINE_PLAN:
            result = self.registry.dispatch(tool_name, arguments)
            trace.append(ToolCallTrace(tool=tool_name, arguments=arguments, result=result))
        return trace

    def _run_live(self) -> list[ToolCallTrace]:
        trace: list[ToolCallTrace] = []
        self._final_narrative = None
        messages = [
            {
                "role": "user",
                "content": (
                    f"Target domain: {self.target_domain}\n"
                    "Perform passive recon and produce the summary described in your instructions."
                ),
            }
        ]

        for _ in range(self.max_iterations):
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=1024,
                    system=SYSTEM_PROMPT,
                    tools=TOOL_SPECS,
                    messages=messages,
                )
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                self._final_narrative = (
                    f"[LLM call failed mid-run, falling back to offline summary: {exc}]"
                )
                if not trace:
                    trace = self._run_offline()
                return trace

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                text_blocks = [b.text for b in response.content if getattr(b, "type", "") == "text"]
                self._final_narrative = "\n".join(text_blocks).strip()
                return trace

            tool_results = []
            for block in response.content:
                if getattr(block, "type", "") != "tool_use":
                    continue
                try:
                    result = self.registry.dispatch(block.name, block.input)
                    trace.append(ToolCallTrace(tool=block.name, arguments=dict(block.input), result=result))
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": str(result)}
                    )
                except Exception as exc:
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": f"error: {exc}",
                            "is_error": True,
                        }
                    )
            messages.append({"role": "user", "content": tool_results})

        self._final_narrative = (
            "[Reached max tool-call iterations before the model produced a final summary; "
            "showing findings gathered so far.]"
        )
        return trace

    def _offline_narrative(self, risk: RiskAssessment) -> str:
        parts = ["[offline heuristic summary — set ANTHROPIC_API_KEY for an agentic LLM-driven run]"]
        parts.append(f"Risk level: {risk.severity.upper()} (score {risk.score}).")

        registry = self.registry
        if registry.dns_results:
            a_records = [
                r.value
                for result in registry.dns_results
                if result.record_type == "A"
                for r in result.records
            ]
            if a_records:
                parts.append(f"Resolves to: {', '.join(a_records)}.")

        if registry.http_finding and registry.http_finding.ok:
            missing = registry.http_finding.missing_security_headers
            if missing:
                parts.append(f"Missing security headers: {', '.join(missing)}.")
            else:
                parts.append("All checked security headers are present.")

        if registry.robots_finding and registry.robots_finding.fetched:
            if registry.robots_finding.disallowed_paths:
                parts.append(
                    f"robots.txt discloses {len(registry.robots_finding.disallowed_paths)} "
                    "disallowed path(s) worth reviewing before active testing."
                )

        if registry.tls_finding and registry.tls_finding.connected:
            if registry.tls_finding.issues:
                parts.append("TLS issues: " + "; ".join(registry.tls_finding.issues) + ".")
            else:
                parts.append(f"TLS looks healthy ({registry.tls_finding.protocol}).")

        parts.append(
            "Recommended next step: review the findings above against the test's rules of "
            "engagement before moving from passive recon to any active testing."
        )
        return " ".join(parts)
