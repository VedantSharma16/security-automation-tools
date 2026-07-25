"""Deterministic offline planner: mirrors the live agent's tool-calling loop
without needing an LLM.

Rather than a free-form language model deciding which tools to call, this
planner extracts candidate entities (IOCs, process names, a hostname) from
the alert text with regexes and calls the same :class:`~agentic_soc.tools.ToolRegistry`
methods the live agent would, in a fixed order. This keeps the tool
demonstrably runnable and testable with zero API dependency, exactly like
the offline fallbacks in the sibling ``ioc-triage-assistant`` and
``log-triage-assistant`` projects -- and produces the same
:class:`~agentic_soc.transcript.AgentTranscript` shape the live agent does,
so callers never need to branch on which planner ran.
"""

from __future__ import annotations

import ipaddress
import re

from agentic_soc.tools import ToolRegistry
from agentic_soc.transcript import (
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    AgentStep,
    AgentTranscript,
    Verdict,
)

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_PROCESS_RE = re.compile(r"\b[A-Za-z0-9_-]+\.exe\b", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"(?:Host(?:name)?|Affected host)\s*:\s*([A-Za-z0-9_.-]+)", re.IGNORECASE)
_DOMAIN_CANDIDATE_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
_KNOWN_TLDS = frozenset("com net org io gov edu biz co info xyz cc app dev".split())

_MAX_ENTITIES_PER_KIND = 5


def _dedup_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered = []
    for value in values:
        key = value.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(value)
    return ordered


def _extract_indicators(text: str) -> list[str]:
    hashes = _SHA256_RE.findall(text) + _SHA1_RE.findall(text) + _MD5_RE.findall(text)
    ips = [m for m in _IPV4_RE.findall(text) if _is_valid_ipv4(m)]

    domains = []
    for match in _DOMAIN_CANDIDATE_RE.finditer(text):
        value = match.group(0)
        if _PROCESS_RE.fullmatch(value):
            continue
        tld = value.rsplit(".", 1)[-1].lower()
        if tld in _KNOWN_TLDS:
            domains.append(value)

    return _dedup_preserve_order(ips + domains + hashes)[:_MAX_ENTITIES_PER_KIND]


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _extract_processes(text: str) -> list[str]:
    return _dedup_preserve_order(_PROCESS_RE.findall(text))[:_MAX_ENTITIES_PER_KIND]


def _extract_hostname(text: str) -> str | None:
    match = _HOSTNAME_RE.search(text)
    return match.group(1) if match else None


def _score_verdict(
    ioc_steps: list[AgentStep], process_steps: list[AgentStep], asset_step: AgentStep | None, technique_score: float
) -> tuple[str, float, list[str]]:
    reasoning: list[str] = []

    high_conf_hits = [s for s in ioc_steps if s.observation.get("matched") and s.observation.get("confidence") == "high"]
    any_hits = [s for s in ioc_steps if s.observation.get("matched")]
    high_risk_procs = [s for s in process_steps if s.observation.get("known_lolbin") and s.observation.get("risk_level") == "high"]
    any_lolbin = [s for s in process_steps if s.observation.get("known_lolbin")]
    asset_criticality = asset_step.observation.get("criticality") if asset_step else None
    asset_is_high_value = asset_criticality in {"critical", "high"}

    if high_conf_hits:
        values = ", ".join(s.observation["indicator"] for s in high_conf_hits)
        reasoning.append(f"High-confidence known-malicious indicator(s) matched local threat intel: {values}.")
    if high_risk_procs:
        values = ", ".join(s.observation["process"] for s in high_risk_procs)
        reasoning.append(f"High-risk LOLBin(s) observed: {values}.")
    if asset_step is not None:
        reasoning.append(
            f"Affected host {asset_step.observation['hostname']} has business criticality "
            f"'{asset_criticality}'."
        )
    if technique_score >= 0.15:
        reasoning.append("Alert narrative closely matches a known ATT&CK technique (see retrieved matches).")

    if high_conf_hits and (high_risk_procs or asset_criticality == "critical"):
        return VERDICT_MALICIOUS, 0.9, reasoning
    if high_conf_hits or (high_risk_procs and asset_is_high_value):
        return VERDICT_MALICIOUS, 0.75, reasoning

    if any_hits or high_risk_procs or (any_lolbin and technique_score >= 0.15):
        if not reasoning:
            reasoning.append("Some indicators or processes required review but none were confirmed malicious.")
        return VERDICT_SUSPICIOUS, 0.55, reasoning

    reasoning.append("No indicators matched local threat intel and no high-risk LOLBins were observed.")
    return VERDICT_BENIGN, 0.7, reasoning


_RECOMMENDED_ACTIONS = {
    VERDICT_MALICIOUS: [
        "Isolate the affected host from the network immediately.",
        "Escalate to incident response / the on-call lead.",
        "Pivot on the confirmed indicators across EDR/SIEM for related activity.",
        "Preserve forensic evidence (memory and disk image) before remediation.",
    ],
    VERDICT_SUSPICIOUS: [
        "Assign to a tier-2 analyst for manual review.",
        "Pivot on the observed indicators/processes across the fleet.",
        "Continue monitoring the host for follow-on activity.",
    ],
    VERDICT_BENIGN: [
        "No action required; close the alert.",
        "Consider tuning the detection rule if this pattern recurs as a false positive.",
    ],
}


class OfflineAgent:
    """Deterministic, rule-based stand-in for the live tool-calling agent."""

    def __init__(self, registry: ToolRegistry | None = None):
        self.registry = registry or ToolRegistry.from_files()

    def investigate(self, alert_text: str) -> AgentTranscript:
        steps: list[AgentStep] = []

        ioc_steps = []
        for value in _extract_indicators(alert_text):
            observation = self.registry.lookup_ioc(value)
            step = AgentStep(
                thought=f"Checking indicator {value} against local threat intel.",
                tool="lookup_ioc",
                tool_input={"indicator": value},
                observation=observation,
            )
            steps.append(step)
            ioc_steps.append(step)

        process_steps = []
        for process_name in _extract_processes(alert_text):
            observation = self.registry.check_process(process_name)
            step = AgentStep(
                thought=f"Checking process {process_name} against known LOLBins.",
                tool="check_process",
                tool_input={"process_name": process_name},
                observation=observation,
            )
            steps.append(step)
            process_steps.append(step)

        asset_step = None
        hostname = _extract_hostname(alert_text)
        if hostname:
            observation = self.registry.get_asset_criticality(hostname)
            asset_step = AgentStep(
                thought=f"Looking up business criticality of host {hostname}.",
                tool="get_asset_criticality",
                tool_input={"hostname": hostname},
                observation=observation,
            )
            steps.append(asset_step)

        technique_observation = self.registry.lookup_attack_technique(alert_text, top_k=2)
        steps.append(
            AgentStep(
                thought="Retrieving MITRE ATT&CK techniques matching the alert narrative.",
                tool="lookup_attack_technique",
                tool_input={"query": alert_text, "top_k": 2},
                observation=technique_observation,
            )
        )
        technique_score = max((m["relevance"] for m in technique_observation["matches"]), default=0.0)

        verdict_label, confidence, reasoning_sentences = _score_verdict(ioc_steps, process_steps, asset_step, technique_score)
        verdict = Verdict(
            verdict=verdict_label,
            confidence=confidence,
            reasoning=" ".join(reasoning_sentences),
            recommended_actions=_RECOMMENDED_ACTIONS[verdict_label],
        )

        return AgentTranscript(alert_text=alert_text, steps=steps, verdict=verdict, llm_backed=False)
