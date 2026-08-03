"""Pluggable executive-summary generation for a scan report.

Same design as the other tools in this repo: the report's structured
findings are the source of truth, and a summarizer only turns them into
prose for a human reader. The LLM is given the structured findings JSON
(with secrets already redacted) -- never raw file contents -- so it cannot
leak an unredacted secret even if asked to.

``TemplateSummarizer`` is deterministic, dependency-free, and the default
used by tests and CI. ``AnthropicSummarizer`` is opt-in (``--llm``) and
requires the ``anthropic`` package plus an API key; if either is missing,
``get_summarizer`` falls back to the template summarizer with a note
explaining why.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are an application security engineer writing the executive summary "
    "of an automated secrets-scan report for a development team. You are "
    "given ONLY a JSON object of structured findings -- secret values are "
    "already redacted, and you have no access to the original files. Do not "
    "invent secrets, files, or commits not present in the JSON. Write three "
    "short sections: 'Executive Summary', 'Highest-Priority Findings', and "
    "'Recommended Remediation' (rotate/revoke exposed credentials, purge "
    "git history if a secret is in an old commit, add prevention like "
    "pre-commit hooks or this scanner in CI). Be concise and specific."
)


class Summarizer(Protocol):
    def summarize(self, report: dict) -> str: ...


class TemplateSummarizer:
    """Deterministic, offline executive summary built from the report's stats."""

    def summarize(self, report: dict) -> str:
        if not report["findings"]:
            return (
                "No hardcoded secrets were detected in the scanned target(s). "
                "No further action is recommended; consider running this scan "
                "in CI on every pull request to keep it that way."
            )

        sev = report["findings_by_severity"]
        lines = [
            f"{report['finding_count']} finding(s), risk score "
            f"{report['risk_score']}/100 ({sev['critical']} critical, {sev['high']} high, "
            f"{sev['medium']} medium, {sev['low']} low).",
            "",
        ]

        git_hits = [f for f in report["findings"] if f.get("source") == "git-history"]
        if git_hits:
            commits = sorted({f["commit"] for f in git_hits if f.get("commit")})
            lines.append(
                f"{len(git_hits)} finding(s) exist only in git history (across "
                f"{len(commits)} commit(s)) and are absent from the current working "
                "tree -- these credentials must still be treated as compromised and "
                "rotated, since anyone with a clone has them."
            )

        critical_or_high = [f for f in report["findings"] if f["severity"] in ("critical", "high")]
        if critical_or_high:
            rule_ids = sorted({f["rule_id"] for f in critical_or_high})
            lines.append(
                f"Highest-priority finding types: {', '.join(rule_ids)}. Treat every "
                "matching credential as burned: rotate/revoke it at the provider, then "
                "remove it from source (and from history, if committed)."
            )

        lines.append("")
        lines.append(
            "Recommended remediation: rotate all flagged credentials immediately, "
            "move secrets to a secrets manager or environment variables injected at "
            "deploy time, add a `.secretsallowlist` entry only for confirmed false "
            "positives, and wire this scanner into CI (`--min-severity high`, "
            "non-zero exit on findings) and/or a pre-commit hook to catch new leaks "
            "before they're pushed."
        )
        return "\n".join(lines)


class AnthropicSummarizer:
    """Sends the structured (already-redacted) report to a Claude model for narrative synthesis."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def summarize(self, report: dict) -> str:
        evidence = {
            "finding_count": report["finding_count"],
            "findings_by_severity": report["findings_by_severity"],
            "risk_score": report["risk_score"],
            "findings": report["findings"],
        }
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(evidence, indent=2)}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def get_summarizer(use_llm: bool, model: str = "claude-sonnet-5") -> Summarizer:
    """Return an AnthropicSummarizer if requested and usable, else TemplateSummarizer."""
    if not use_llm:
        return TemplateSummarizer()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "note: --llm requested but ANTHROPIC_API_KEY is not set; "
            "falling back to the offline template summarizer.",
            file=sys.stderr,
        )
        return TemplateSummarizer()

    try:
        return AnthropicSummarizer(model=model, api_key=api_key)
    except ImportError:
        print(
            "note: --llm requested but the 'anthropic' package is not installed; "
            "falling back to the offline template summarizer.",
            file=sys.stderr,
        )
        return TemplateSummarizer()
