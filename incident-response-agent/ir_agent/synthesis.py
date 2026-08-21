"""Deterministic scoring and verdict synthesis from gathered tool evidence.

Used both as the offline planner's synthesizer and as the safety net when the
LLM planner runs out of steps before calling ``finish`` itself.
"""

from __future__ import annotations

from ir_agent.models import IncidentVerdict, ToolResult

_CONFIDENCE_WEIGHT = {"high": 3, "medium": 2, "low": 1}

_SEVERITY_THRESHOLDS = (
    ("critical", 7),
    ("high", 4),
    ("medium", 2),
)


def _score_evidence(evidence: list[ToolResult]) -> int:
    score = 0
    for result in evidence:
        if result.tool in ("check_ip_reputation", "check_domain_reputation") and result.malicious:
            confidence = result.detail.get("confidence", "low")
            score += _CONFIDENCE_WEIGHT.get(confidence, 1)
        elif result.tool == "check_cve" and result.malicious:
            if result.detail.get("known_exploited"):
                score += 4
            elif result.detail.get("severity") == "critical":
                score += 4
            elif result.detail.get("severity") == "high":
                score += 3
            else:
                score += 1
    return score


def _severity_from_score(score: int) -> str:
    for label, threshold in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def _has_known_exploited_cve(evidence: list[ToolResult]) -> bool:
    return any(e.tool == "check_cve" and e.detail.get("known_exploited") for e in evidence)


def _recommended_actions(evidence: list[ToolResult], severity: str) -> list[str]:
    actions: list[str] = []
    malicious_ips = [e for e in evidence if e.tool == "check_ip_reputation" and e.malicious]
    malicious_domains = [e for e in evidence if e.tool == "check_domain_reputation" and e.malicious]
    exploited_cves = [
        e for e in evidence if e.tool == "check_cve" and e.malicious and e.detail.get("known_exploited")
    ]

    if malicious_ips:
        ips = ", ".join(e.tool_input for e in malicious_ips)
        actions.append(f"Block/monitor known-malicious IP(s) at the perimeter: {ips}.")
    if malicious_domains:
        domains = ", ".join(e.tool_input for e in malicious_domains)
        actions.append(f"Sinkhole/block known-malicious domain(s) at DNS/proxy: {domains}.")
    if exploited_cves:
        cves = ", ".join(e.tool_input for e in exploited_cves)
        actions.append(f"Patch or compensating-control affected systems for actively exploited {cves} immediately.")

    if severity in ("critical", "high"):
        actions.append("Isolate the affected host(s) pending analyst confirmation.")
        actions.append("Pivot on all flagged indicators in EDR/SIEM to scope related activity.")
    elif not actions:
        actions.append(
            "No known-malicious indicators or exploited CVEs found in local intel; "
            "monitor and escalate only if additional context emerges."
        )
    else:
        actions.append("Document findings and continue monitoring for related activity.")

    return actions


def synthesize_verdict(
    incident_text: str,
    evidence: list[ToolResult],
    trace: list,
    llm_backed: bool = False,
) -> IncidentVerdict:
    """Build a final :class:`IncidentVerdict` deterministically from gathered evidence."""
    score = _score_evidence(evidence)
    severity = _severity_from_score(score)
    if _has_known_exploited_cve(evidence):
        # A CVE with confirmed in-the-wild exploitation is always at least
        # critical, regardless of how it stacks up against other evidence.
        severity = "critical"
    malicious_hits = [e for e in evidence if e.malicious]
    confidence = min(0.95, 0.35 + 0.15 * len(malicious_hits)) if malicious_hits else 0.4

    technique_hits = [e for e in evidence if e.tool == "lookup_attack_technique" and e.detail]

    parts = [f"[offline heuristic verdict] Severity: {severity.upper()} (evidence score {score})."]
    if malicious_hits:
        named = ", ".join(f"{e.tool_input} ({e.tool})" for e in malicious_hits)
        parts.append(f"Confirmed against local intel: {named}.")
    else:
        parts.append("No indicators in the incident text matched local threat intel or the CVE database.")
    if technique_hits:
        parts.append(technique_hits[0].summary)

    return IncidentVerdict(
        severity=severity,
        confidence=confidence,
        summary=" ".join(parts),
        recommended_actions=_recommended_actions(evidence, severity),
        evidence=evidence,
        trace=trace,
        llm_backed=llm_backed,
    )
