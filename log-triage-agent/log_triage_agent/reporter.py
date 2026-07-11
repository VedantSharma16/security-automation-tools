"""Turns Findings + retrieved ATT&CK context into an analyst-readable
Markdown incident report.

Narrative generation is pluggable: `TemplateNarrator` is a fully offline,
deterministic fallback (no dependencies, no network, no API key), while
`AnthropicNarrator` is an optional "agentic" enrichment step that asks
Claude to write the executive summary once retrieval has grounded it in the
actual detections and ATT&CK context. `get_default_narrator()` picks
whichever is available so the tool always works out of the box.
"""

import os
from typing import List, Optional

from .knowledge_base import AttackKnowledgeBase, Technique
from .models import Finding, Severity

_SEVERITY_RANK = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 2,
    Severity.MEDIUM: 1,
    Severity.LOW: 0,
}

RECOMMENDED_ACTIONS = {
    "brute_force": [
        "Block or rate-limit the source IP at the firewall/WAF.",
        "Confirm whether any targeted account authenticated successfully.",
        "Enable or verify account lockout / fail2ban-style throttling.",
    ],
    "password_spray": [
        "Block the source IP and review conditional access / geo-fencing policies.",
        "Force password resets for any targeted accounts that succeeded.",
        "Check for spraying from the same IP/ASN against other services.",
    ],
    "credential_success_after_failures": [
        "Treat the account as compromised: force a credential reset immediately.",
        "Review session/command history for the account since the login time.",
        "Check for lateral movement or privilege escalation from this session.",
    ],
    "off_hours_login": [
        "Confirm the login with the account owner if feasible.",
        "Correlate with VPN/badge data to see if the access is plausible.",
        "No action needed if this matches known on-call/maintenance activity.",
    ],
}


class TemplateNarrator:
    """Deterministic, dependency-free narrative generator."""

    def narrate(self, finding: Finding, techniques: List[Technique]) -> str:
        if techniques:
            technique_list = "; ".join(f"{t.id} ({t.name})" for t in techniques)
            mapping_clause = f" This maps to {technique_list}."
        else:
            mapping_clause = ""
        return (
            f"{finding.summary}{mapping_clause} "
            f"Severity assessed as {finding.severity.value.upper()} based on "
            f"{len(finding.events)} correlated log event(s)."
        )


class AnthropicNarrator:
    """Uses the Claude API to write a short narrative grounded in the
    retrieved ATT&CK context. Any failure (missing package, missing key,
    network error) falls back to the TemplateNarrator so the pipeline never
    breaks because of the optional enrichment step."""

    def __init__(self, model: str = "claude-sonnet-5"):
        import anthropic  # imported lazily so the package is truly optional

        self._client = anthropic.Anthropic()
        self._model = model
        self._fallback = TemplateNarrator()

    def narrate(self, finding: Finding, techniques: List[Technique]) -> str:
        context = "\n".join(f"- {t.id} {t.name}: {t.description}" for t in techniques)
        prompt = (
            "You are a SOC analyst writing one concise paragraph (2-3 sentences) "
            "for an incident report. Use only the facts given below, do not "
            "invent details.\n\n"
            f"Detection: {finding.summary}\n"
            f"Severity: {finding.severity.value}\n"
            f"Relevant MITRE ATT&CK context:\n{context or 'None'}\n\n"
            "Write the paragraph now."
        )
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text.strip()
        except Exception:
            return self._fallback.narrate(finding, techniques)


def get_default_narrator():
    """Returns an AnthropicNarrator if the SDK is installed and an API key
    is configured, otherwise falls back to the offline TemplateNarrator."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            return AnthropicNarrator()
        except Exception:
            pass
    return TemplateNarrator()


def generate_report(
    findings: List[Finding],
    kb: Optional[AttackKnowledgeBase] = None,
    narrator=None,
) -> str:
    kb = kb or AttackKnowledgeBase()
    narrator = narrator or get_default_narrator()

    if not findings:
        return "# Log Triage Report\n\nNo suspicious activity detected.\n"

    ordered = sorted(findings, key=lambda f: _SEVERITY_RANK[f.severity], reverse=True)

    lines = ["# Log Triage Report", "", f"**{len(findings)} finding(s) detected.**", ""]
    for i, finding in enumerate(ordered, start=1):
        techniques = kb.retrieve_for_finding(finding.finding_type, finding.summary)
        narrative = narrator.narrate(finding, techniques)

        lines.append(f"## {i}. {finding.finding_type.replace('_', ' ').title()} "
                      f"[{finding.severity.value.upper()}]")
        lines.append("")
        lines.append(f"**Source IP:** {finding.source_ip}")
        lines.append("")
        lines.append(narrative)
        lines.append("")
        if techniques:
            lines.append("**MITRE ATT&CK mapping:**")
            for t in techniques:
                lines.append(f"- [{t.id}]({t.url}) {t.name} ({t.tactic})")
            lines.append("")
        actions = RECOMMENDED_ACTIONS.get(finding.finding_type, [])
        if actions:
            lines.append("**Recommended actions:**")
            for action in actions:
                lines.append(f"- {action}")
            lines.append("")

    return "\n".join(lines)
