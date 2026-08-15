"""False-positive triage and an optional LLM-generated analyst narrative.

Secret scanners are only useful if their output is actionable — a report
that's 90% test fixtures and placeholder strings trains developers to
ignore it. :func:`triage_findings` applies deterministic, explainable
heuristics to flag likely false positives *before* anything reaches an LLM,
which keeps the (optional) narrative step cheap, fast, and grounded in the
same signal a human reviewer would use.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .scanner import Finding

DEFAULT_MODEL = "claude-sonnet-5"

FALSE_POSITIVE_PATH_HINTS = (
    "test", "tests", "example", "examples", "sample", "samples",
    "fixture", "fixtures", "mock", "mocks", "doc", "docs", "spec",
)

# Whole-word match only: a plain substring check would misfire on legitimate
# paths like `latest_config.py`, `contest_entries/`, or `attestation.py`.
_PATH_HINT_RE = re.compile(r"(?i)\b(?:" + "|".join(FALSE_POSITIVE_PATH_HINTS) + r")\b")

FALSE_POSITIVE_VALUE_HINTS = (
    "xxxx", "0000", "1234", "changeme", "change_me", "example",
    "your_", "your-", "placeholder", "dummy", "redacted", "fake",
    "sample", "todo", "insert_", "replace_", "<key>", "<token>",
)

SYSTEM_PROMPT = (
    "You are an application security engineer triaging output from an "
    "automated secret scanner. Given a list of findings (already redacted "
    "and pre-screened for likely false positives), write a concise summary: "
    "what needs immediate credential rotation, what's probably noise and "
    "why, and the top 2-4 remediation actions in priority order. Be direct."
)


@dataclass(frozen=True)
class TriagedFinding:
    finding: Finding
    likely_false_positive: bool
    reasons: tuple[str, ...]
    source: str = "working-tree"  # or "git-history"


def triage_finding(finding: Finding, source: str = "working-tree") -> TriagedFinding:
    reasons: list[str] = []
    line_lower = finding.line_preview.lower()

    if _PATH_HINT_RE.search(finding.file):
        reasons.append("file path suggests test/example/fixture content")

    if any(hint in line_lower for hint in FALSE_POSITIVE_VALUE_HINTS):
        reasons.append("line contains placeholder-like wording")

    if finding.detector == "entropy" and finding.severity == "low":
        reasons.append("entropy-only match with no known credential format")

    return TriagedFinding(
        finding=finding,
        likely_false_positive=bool(reasons),
        reasons=tuple(reasons),
        source=source,
    )


def triage_findings(
    findings: list[Finding], source: str = "working-tree"
) -> list[TriagedFinding]:
    return [triage_finding(f, source=source) for f in findings]


def _build_prompt(triaged: list[TriagedFinding], target: str) -> str:
    likely_real = [t for t in triaged if not t.likely_false_positive]
    likely_fp = [t for t in triaged if t.likely_false_positive]

    lines = [f"## Secret scan of {target}", ""]

    lines.append(f"## Likely genuine findings ({len(likely_real)})")
    if likely_real:
        for t in likely_real:
            f = t.finding
            lines.append(
                f"- [{f.severity.upper()}] {f.pattern_name} in {f.file}:{f.line_number} "
                f"(source={t.source}, value={f.redacted_value})"
            )
    else:
        lines.append("- none")

    lines.append("")
    lines.append(f"## Likely false positives ({len(likely_fp)})")
    if likely_fp:
        for t in likely_fp:
            f = t.finding
            lines.append(
                f"- [{f.severity.upper()}] {f.pattern_name} in {f.file}:{f.line_number} "
                f"— {', '.join(t.reasons)}"
            )
    else:
        lines.append("- none")

    return "\n".join(lines)


class SecretTriageClient:
    """Wraps Anthropic API access with a safe offline fallback, mirroring the
    pattern used across this repo's other triage tools so the CLI works —
    and tests run — with no network access or API key required."""

    def __init__(self, use_llm: bool = False, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        if use_llm and self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def narrate(self, triaged: list[TriagedFinding], target: str) -> str:
        prompt = _build_prompt(triaged, target)
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=500,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return self._offline_narrative(triaged) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
        return self._offline_narrative(triaged)

    @staticmethod
    def _offline_narrative(triaged: list[TriagedFinding]) -> str:
        likely_real = [t for t in triaged if not t.likely_false_positive]
        likely_fp = [t for t in triaged if t.likely_false_positive]
        critical = [t for t in likely_real if t.finding.severity == "critical"]

        parts = [
            "[offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis]",
            f"{len(triaged)} finding(s): {len(likely_real)} likely genuine, "
            f"{len(likely_fp)} likely false positive(s).",
        ]

        if critical:
            names = ", ".join(f"{t.finding.pattern_name} ({t.finding.file}:{t.finding.line_number})" for t in critical)
            parts.append(f"CRITICAL — rotate immediately: {names}.")
        elif likely_real:
            parts.append("No critical-severity findings, but review and rotate flagged credentials as a precaution.")
        else:
            parts.append("No high-confidence findings; remaining items look like test/placeholder data.")

        parts.append(
            "Recommended next steps: rotate any confirmed live credentials, add "
            "a 'pragma: allowlist secret' comment to accepted false positives so "
            "they stop reappearing in future scans, and if any critical/high "
            "finding appears in git history, treat the repository's remote copies "
            "as compromised until the credential is revoked."
        )
        return " ".join(parts)
