"""Orchestrates detection + narrative summarization into a single Report.

The narrative step is pluggable behind the TriageClient interface so the agent works
fully offline (DeterministicTriageClient) and can optionally be upgraded to a real LLM
call (AnthropicTriageClient) without changing any calling code. This mirrors how you'd
wire an LLM into a larger pipeline: keep the deterministic core testable and put the
non-deterministic model call behind a narrow, swappable seam.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from log_triage_agent.detectors import DetectorConfig, run_all_detectors
from log_triage_agent.ioc import extract_iocs
from log_triage_agent.models import Finding, IOCs, Report

DEFAULT_MODEL = "claude-sonnet-5"

_SYSTEM_PROMPT = (
    "You are a SOC tier-1 triage assistant. Given a list of security findings extracted "
    "from auth logs, write a concise incident summary for a human analyst. Prioritize by "
    "severity, call out the MITRE ATT&CK techniques involved, and end with 2-4 concrete "
    "next steps (e.g. block IP, force password reset, review sudoers). Keep it under 200 words. "
    "Plain text, no markdown headers."
)


class TriageClient(ABC):
    """Interface for anything that can turn findings into a narrative summary."""

    #: Short label recorded on the Report so consumers know how the narrative was produced.
    source_name = "unknown"

    @abstractmethod
    def summarize(self, findings: list[Finding], iocs: IOCs, events_analyzed: int) -> str:
        raise NotImplementedError


class DeterministicTriageClient(TriageClient):
    """Template-based summary. No network calls, no API key — always available, always
    the same output for the same input, which makes it the right default for tests and
    for offline/air-gapped use.
    """

    source_name = "deterministic"

    def summarize(self, findings: list[Finding], iocs: IOCs, events_analyzed: int) -> str:
        if not findings:
            return (
                f"Analyzed {events_analyzed} event(s) across {len(iocs.source_ips)} source "
                "IP(s). No findings crossed detection thresholds; nothing actionable."
            )

        top_severity = max((f.severity for f in findings), key=lambda s: s.rank)
        lines = [
            f"Analyzed {events_analyzed} event(s); {len(findings)} finding(s) raised, "
            f"highest severity {top_severity.value.upper()}."
        ]
        for f in findings:
            lines.append(f"- [{f.severity.value.upper()}] {f.title} ({f.technique_id} {f.technique_name})")

        actions = ["Recommended next steps:"]
        if any(f.technique_id == "T1110" for f in findings):
            actions.append("- Block or rate-limit the flagged source IP(s) at the firewall.")
        if any(f.technique_id == "T1078" for f in findings):
            actions.append("- Force a password reset and review session history for the affected account(s).")
        if any(f.technique_id.startswith("T1548") for f in findings):
            actions.append("- Review sudoers policy and the specific commands run as root.")
        if any(f.technique_id == "T1087" for f in findings):
            actions.append("- Add the source IP to a watchlist; enumeration often precedes brute-forcing.")
        actions.append("- Correlate source IPs against threat intel feeds before deciding to block.")

        return "\n".join(lines + [""] + actions)


class AnthropicTriageClient(TriageClient):
    """Calls the Anthropic API to generate the narrative. Import of the SDK is deferred
    to __init__ so the rest of the package has zero hard dependency on it.
    """

    source_name = "llm"

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        import anthropic  # deferred import: only required if this client is actually used

        self._client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self._model = model

    def summarize(self, findings: list[Finding], iocs: IOCs, events_analyzed: int) -> str:
        if not findings:
            return DeterministicTriageClient().summarize(findings, iocs, events_analyzed)

        findings_payload = [f.to_dict() for f in findings]
        user_prompt = (
            f"Events analyzed: {events_analyzed}\n"
            f"Source IPs involved: {iocs.source_ips}\n"
            f"Usernames involved: {iocs.usernames}\n"
            f"Findings (JSON): {findings_payload}"
        )
        response = self._client.messages.create(
            model=self._model,
            max_tokens=500,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text").strip()


def resolve_default_client() -> TriageClient:
    """Use the LLM client when an API key is configured, otherwise fall back to the
    deterministic one so the CLI always works out of the box.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            return AnthropicTriageClient()
        except ImportError:
            return DeterministicTriageClient()
    return DeterministicTriageClient()


class TriageAgent:
    """Runs detectors over a batch of events and produces a Report, delegating the
    narrative summary to a pluggable TriageClient.
    """

    def __init__(self, client: TriageClient | None = None, config: DetectorConfig | None = None):
        self._client = client or resolve_default_client()
        self._config = config or DetectorConfig()

    def run(self, events: list) -> Report:
        findings = run_all_detectors(events, self._config)
        iocs = extract_iocs(events)
        narrative = self._client.summarize(findings, iocs, len(events))

        return Report(
            findings=findings,
            iocs=iocs,
            events_analyzed=len(events),
            narrative=narrative,
            narrative_source=self._client.source_name,
        )
