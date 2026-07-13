"""Triage summary generation for a threat report / log excerpt.

Two backends:

- ``HeuristicSummarizer`` — always available, zero dependencies. Produces a
  deterministic extractive summary plus a rule-based severity score. This is
  what tests run against and what the CLI falls back to.
- ``ClaudeSummarizer`` — optional. If ``ANTHROPIC_API_KEY`` is set and the
  ``anthropic`` package is installed, asks Claude to turn the extracted IOCs
  and ATT&CK hits into an analyst-facing narrative summary and next steps.

Both implement the same ``Summarizer`` protocol so the CLI can pick one at
runtime without caring which backend produced the result.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Protocol

from ioc_toolkit.enrichment import AttackHit
from ioc_toolkit.extractor import ExtractionResult

_HIGH_RISK_TYPES = {"sha256", "sha1", "md5", "cve"}


@dataclass
class TriageSummary:
    severity: str
    score: int
    narrative: str
    recommended_actions: list


class Summarizer(Protocol):
    def summarize(
        self, text: str, extraction: ExtractionResult, attack_hits: list
    ) -> TriageSummary: ...


class HeuristicSummarizer:
    """Deterministic, dependency-free triage summary based on simple counts.

    Not a substitute for analyst judgement — it exists so the toolkit is
    always usable, and so the CLI/tests never depend on network access or an
    API key.
    """

    def summarize(
        self, text: str, extraction: ExtractionResult, attack_hits: list
    ) -> TriageSummary:
        counts = extraction.to_dict()
        score = 0
        score += 3 * sum(len(counts[t]) for t in _HIGH_RISK_TYPES)
        score += 2 * len(attack_hits)
        score += 1 * (len(counts["ipv4"]) + len(counts["ipv6"]) + len(counts["domain"]) + len(counts["url"]))

        if score >= 15:
            severity = "high"
        elif score >= 6:
            severity = "medium"
        elif score > 0:
            severity = "low"
        else:
            severity = "informational"

        parts = [f"Extracted {len(extraction)} indicator(s) across {sum(1 for v in counts.values() if v)} type(s)."]
        if attack_hits:
            techniques = ", ".join(f"{h.keyword} ({h.technique_id or 'no technique ID'})" for h in attack_hits)
            parts.append(f"Matched {len(attack_hits)} known offensive-tool keyword(s): {techniques}.")
        if counts["cve"]:
            parts.append(f"References {len(counts['cve'])} CVE(s): {', '.join(counts['cve'])}.")
        narrative = " ".join(parts) if len(extraction) or attack_hits else "No indicators or known offensive tooling detected in the supplied text."

        actions = []
        if counts["sha256"] or counts["sha1"] or counts["md5"]:
            actions.append("Submit file hashes to your EDR/AV and threat-intel platform for prevalence and reputation.")
        if counts["ipv4"] or counts["ipv6"] or counts["domain"] or counts["url"]:
            actions.append("Check network/proxy/DNS logs for connections to the extracted hosts and add confirmed-bad ones to blocklists.")
        if attack_hits:
            actions.append("Cross-reference matched ATT&CK techniques against detection coverage and hunt for related activity.")
        if counts["cve"]:
            actions.append("Check asset inventory for exposure to the referenced CVE(s) and confirm patch status.")
        if not actions:
            actions.append("No action required based on automated triage; consider manual review if context suggests otherwise.")

        return TriageSummary(severity=severity, score=score, narrative=narrative, recommended_actions=actions)


class ClaudeSummarizer:
    """LLM-backed narrative summary using the Claude API.

    Requires the ``anthropic`` package and ``ANTHROPIC_API_KEY``. The client
    is created lazily (not at import time) so importing this module never
    requires the dependency or the key to be present.
    """

    def __init__(self, model: str = "claude-sonnet-5", client=None):
        self.model = model
        self._client = client

    def _get_client(self):
        if self._client is not None:
            return self._client
        import anthropic  # local import: optional dependency

        self._client = anthropic.Anthropic()
        return self._client

    def summarize(
        self, text: str, extraction: ExtractionResult, attack_hits: list
    ) -> TriageSummary:
        client = self._get_client()
        counts = extraction.to_dict()
        attack_lines = "\n".join(
            f"- {h.keyword}: {h.technique_name} ({h.technique_id or 'no ATT&CK ID'}), tactic: {h.tactic}"
            for h in attack_hits
        ) or "none"

        prompt = (
            "You are assisting a SOC analyst with triage. Given the extracted "
            "indicators and matched ATT&CK techniques below (and the raw "
            "report text for context), respond with exactly three sections:\n"
            "SEVERITY: one of informational/low/medium/high\n"
            "NARRATIVE: 2-4 sentences summarizing what this report/log excerpt represents\n"
            "ACTIONS: a bullet list of concrete next steps for the analyst\n\n"
            f"Indicators found: {counts}\n"
            f"ATT&CK matches:\n{attack_lines}\n\n"
            f"Raw text (truncated):\n{text[:4000]}"
        )

        response = client.messages.create(
            model=self.model,
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        content = "".join(block.text for block in response.content if hasattr(block, "text"))
        return _parse_llm_response(content)


def _parse_llm_response(content: str) -> TriageSummary:
    severity_match = re.search(r"SEVERITY:\s*(\w+)", content, re.IGNORECASE)
    narrative_match = re.search(r"NARRATIVE:\s*(.+?)(?=ACTIONS:|$)", content, re.IGNORECASE | re.DOTALL)
    actions_match = re.search(r"ACTIONS:\s*(.+)", content, re.IGNORECASE | re.DOTALL)

    severity = severity_match.group(1).lower() if severity_match else "informational"
    narrative = narrative_match.group(1).strip() if narrative_match else content.strip()
    actions_raw = actions_match.group(1).strip() if actions_match else ""
    actions = [
        line.lstrip("-*• ").strip()
        for line in actions_raw.splitlines()
        if line.strip()
    ] or ["Review the narrative above and determine next steps manually."]

    score_by_severity = {"informational": 0, "low": 3, "medium": 9, "high": 18}
    score = score_by_severity.get(severity, 0)

    return TriageSummary(severity=severity, score=score, narrative=narrative, recommended_actions=actions)


def get_summarizer() -> Summarizer:
    """Pick the best available summarizer: Claude if configured, otherwise
    the built-in heuristic backend."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa: F401

            return ClaudeSummarizer()
        except ImportError:
            pass
    return HeuristicSummarizer()
