"""Pluggable narrator backends that turn triage evidence into an analyst-readable summary.

`RuleBasedNarrator` is the default: fully offline and deterministic, so the
CLI and test suite work with zero API keys or network access. `ClaudeNarrator`
is an optional drop-in that calls the Claude API for a natural-language
summary when ANTHROPIC_API_KEY is configured.
"""

from typing import List, Protocol

from .models import Alert, TechniqueMatch


class TriageNarrator(Protocol):
    def summarize(
        self, alert: Alert, matches: List[TechniqueMatch], indicators: List[str], severity: str
    ) -> str: ...


class RuleBasedNarrator:
    """Deterministic, offline narrator used by default and in tests."""

    def summarize(
        self, alert: Alert, matches: List[TechniqueMatch], indicators: List[str], severity: str
    ) -> str:
        top = matches[0] if matches else None
        technique_str = f"{top.name} ({top.technique_id})" if top and top.score > 0 else "no strong technique match"
        indicator_str = "; ".join(indicators) if indicators else "no known offensive indicators"
        return (
            f"[{severity.upper()}] Alert {alert.id} on host {alert.host} (user {alert.user}) "
            f"most closely resembles {technique_str}. Indicators: {indicator_str}."
        )


class ClaudeNarrator:
    """Optional narrator backed by the Claude API.

    Requires the `anthropic` package and an ANTHROPIC_API_KEY in the
    environment. Import is deferred so the package has zero hard
    dependencies unless this backend is explicitly requested.
    """

    def __init__(self, model: str = "claude-sonnet-5"):
        import anthropic  # noqa: PLC0415

        self._client = anthropic.Anthropic()
        self._model = model

    def summarize(
        self, alert: Alert, matches: List[TechniqueMatch], indicators: List[str], severity: str
    ) -> str:
        technique_summary = ", ".join(f"{m.name} ({m.technique_id}, score={m.score:.2f})" for m in matches)
        prompt = (
            f"You are a SOC analyst. Alert: {alert.text()}\n"
            f"Candidate MITRE ATT&CK techniques: {technique_summary}\n"
            f"Heuristic indicators: {', '.join(indicators) or 'none'}\n"
            f"Heuristic severity: {severity}\n"
            "Write a 2-sentence triage summary and confirm or challenge the severity."
        )
        response = self._client.messages.create(
            model=self._model,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
