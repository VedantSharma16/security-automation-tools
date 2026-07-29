"""LLM-assisted triage for ambiguous, low/medium-confidence findings.

High-confidence named signatures (an AWS key, a PEM private key block, ...)
don't need a second opinion. The generic entropy-based detector is
precision/recall-tradeoff by design, though, and *will* flag some UUIDs,
hashes, and test fixtures alongside real secrets. This module asks an LLM to
weigh in on just that ambiguous subset, grounded only in metadata that's
already safe to share: the redacted value preview, its entropy, and the
detector's own description — never the raw secret. That keeps a third-party
API call from ever becoming a second place a secret could leak to.

Without ``ANTHROPIC_API_KEY`` set (or without the ``anthropic`` package
installed), triage falls back to a deterministic entropy/confidence
heuristic, so the tool is fully usable and testable offline.
"""

from __future__ import annotations

import os
import re

from .scanner import Finding

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a security engineer triaging a possible secret-leak finding from an "
    "automated scanner. You are given ONLY a redacted preview of the value, its "
    "Shannon entropy, and the detector's rationale -- never the real secret. "
    "Decide whether this is most likely a true positive (a real credential/secret), "
    "a false positive (placeholder, test fixture, UUID, hash, non-secret identifier), "
    "or genuinely uncertain. Respond in exactly this format on two lines:\n"
    "VERDICT: <true_positive|false_positive|uncertain>\n"
    "RATIONALE: <one concise sentence>"
)

_VERDICT_RE = re.compile(
    r"VERDICT:\s*(true_positive|false_positive|uncertain)", re.IGNORECASE
)
_RATIONALE_RE = re.compile(r"RATIONALE:\s*(.+)", re.IGNORECASE)

# Only these confidences benefit from a second opinion; "high" confidence
# named signatures are treated as settled without spending an LLM call.
TRIAGEABLE_CONFIDENCES = {"low", "medium"}


def build_prompt(finding: Finding) -> str:
    return (
        f"File: {finding.file}\n"
        f"Line: {finding.line_number}\n"
        f"Category: {finding.category}\n"
        f"Detector: {finding.signature_id}\n"
        f"Description: {finding.description}\n"
        f"Redacted value preview: {finding.redacted_value}\n"
        f"Entropy: {finding.entropy} bits/char\n"
    )


def _parse_verdict(text: str, finding: Finding) -> dict:
    verdict_match = _VERDICT_RE.search(text)
    rationale_match = _RATIONALE_RE.search(text)
    verdict = verdict_match.group(1).lower() if verdict_match else "uncertain"
    rationale = rationale_match.group(1).strip() if rationale_match else text.strip()
    return {"fingerprint": finding.fingerprint, "verdict": verdict, "rationale": rationale}


def _offline_triage(finding: Finding) -> dict:
    if finding.confidence == "high":
        verdict, rationale = (
            "true_positive",
            "Matched a high-confidence, vendor-specific signature format.",
        )
    elif finding.entropy >= 4.2:
        verdict, rationale = (
            "likely_true_positive",
            f"Very high entropy ({finding.entropy} bits/char) for a generic secret-shaped value.",
        )
    elif finding.entropy >= 3.5:
        verdict, rationale = (
            "uncertain",
            f"Moderate entropy ({finding.entropy}); could be a real secret or a "
            "random-looking test fixture / UUID / hash.",
        )
    else:
        verdict, rationale = (
            "likely_false_positive",
            f"Low entropy ({finding.entropy}) for a claimed secret value; likely a "
            "placeholder or short non-secret token.",
        )
    return {
        "fingerprint": finding.fingerprint,
        "verdict": verdict,
        "rationale": f"[offline heuristic — set ANTHROPIC_API_KEY for LLM-based triage] {rationale}",
    }


class LLMTriageClient:
    """Wraps Anthropic API access with a safe, deterministic offline fallback."""

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

    def triage(self, finding: Finding) -> dict:
        if self._client is None:
            return _offline_triage(finding)

        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=100,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": build_prompt(finding)}],
            )
            text = "".join(
                block.text for block in response.content if getattr(block, "type", "") == "text"
            ).strip()
            return _parse_verdict(text, finding)
        except Exception as exc:  # pragma: no cover - network/SDK failure path
            fallback = _offline_triage(finding)
            fallback["rationale"] += f" [LLM call failed, offline fallback used: {exc}]"
            return fallback


def triage_findings(findings: list[Finding], client: LLMTriageClient) -> dict[str, dict]:
    """Triage every ambiguous finding; returns a fingerprint -> verdict map."""
    verdicts = {}
    for finding in findings:
        if finding.confidence not in TRIAGEABLE_CONFIDENCES:
            continue
        verdicts[finding.fingerprint] = client.triage(finding)
    return verdicts
