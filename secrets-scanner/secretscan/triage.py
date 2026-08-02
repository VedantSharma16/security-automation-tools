"""Optional LLM-assisted triage for lower-confidence findings.

Vendor-specific rule matches (AWS key IDs, GitHub PATs, ...) have a low
false-positive rate on their own, so triage skips straight to a
``likely_secret`` verdict for those without spending an API call. Generic
high-entropy findings are the noisy category -- test fixtures, hashes,
build IDs, and UUIDs all trip the entropy detector -- so those are the ones
worth a second opinion.

Only redacted, structural metadata is ever sent to the model: file path,
rule/category, entropy score, and the already-masked preview
(``secretscan.scanner.redact``). The raw secret value never leaves the
process, live LLM mode or not.

Without ``ANTHROPIC_API_KEY`` (or the ``anthropic`` package), triage falls
back to a deterministic offline heuristic, so the tool -- and its test
suite -- work fully offline.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

DEFAULT_MODEL = "claude-sonnet-5"

VERDICTS = ("likely_secret", "likely_false_positive", "uncertain")

_NON_SECRET_PATH_HINTS = ("test", "tests", "fixture", "fixtures", "example", "examples", "sample", "doc", "docs", "mock")

SYSTEM_PROMPT = (
    "You are an application security engineer triaging automated secret-scanner "
    "findings. You are given ONLY metadata about a potential secret -- file path, "
    "matched category, an already-redacted preview, and an entropy score -- never "
    "the raw secret value, and you must not ask for it. Decide whether this is "
    "likely a real secret or a false positive (test fixture, placeholder, "
    "documentation example, or a non-secret high-entropy string like a hash or "
    "UUID). Respond in exactly this format, nothing else:\n"
    "VERDICT: <likely_secret|likely_false_positive|uncertain>\n"
    "RATIONALE: <one concise sentence>"
)

_RESPONSE_PATTERN = re.compile(
    r"VERDICT:\s*(likely_secret|likely_false_positive|uncertain)\s*\n\s*RATIONALE:\s*(.+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TriageResult:
    verdict: str
    rationale: str
    source: str  # "offline" or "llm"


def _offline_triage(finding) -> TriageResult:
    if finding.detector == "rule":
        return TriageResult(
            verdict="likely_secret",
            rationale="Matched a vendor-specific token format, which has a low false-positive rate.",
            source="offline",
        )

    path_lower = finding.file_path.lower()
    if any(hint in path_lower for hint in _NON_SECRET_PATH_HINTS):
        return TriageResult(
            verdict="likely_false_positive",
            rationale=f"File path '{finding.file_path}' suggests test/example/documentation content.",
            source="offline",
        )

    return TriageResult(
        verdict="uncertain",
        rationale=(
            "Generic high-entropy value with no vendor format match; provenance can't "
            "be determined from static heuristics alone -- set ANTHROPIC_API_KEY for a "
            "model-assisted opinion."
        ),
        source="offline",
    )


def _build_prompt(finding) -> str:
    return (
        f"File: {finding.file_path}:{finding.line_number}\n"
        f"Rule/category: {finding.rule_id} ({finding.category})\n"
        f"Detector: {finding.detector}\n"
        f"Redacted preview: {finding.preview}\n"
        f"Description: {finding.description}"
    )


class Triager:
    """Wraps optional Anthropic API access with an offline fallback."""

    def __init__(self, use_llm: bool = False, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
        self._client = None
        if use_llm:
            api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if api_key:
                try:
                    import anthropic  # type: ignore

                    self._client = anthropic.Anthropic(api_key=api_key)
                except ImportError:
                    self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def triage(self, finding) -> TriageResult:
        # Rule-based matches are cheap to classify offline and don't need a
        # model call; only ambiguous entropy findings go to the LLM.
        if self._client is None or finding.detector == "rule":
            return _offline_triage(finding)

        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=150,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": _build_prompt(finding)}],
            )
            text = "".join(
                block.text for block in response.content if getattr(block, "type", "") == "text"
            ).strip()
            match = _RESPONSE_PATTERN.search(text)
            if not match:
                return _offline_triage(finding)
            return TriageResult(verdict=match.group(1).lower(), rationale=match.group(2).strip(), source="llm")
        except Exception:  # pragma: no cover - network/SDK failure path
            return _offline_triage(finding)


def triage_findings(findings: list, use_llm: bool = False, model: str = DEFAULT_MODEL) -> dict:
    """Return a dict mapping finding.fingerprint -> TriageResult for every finding."""
    triager = Triager(use_llm=use_llm, model=model)
    return {finding.fingerprint: triager.triage(finding) for finding in findings}
