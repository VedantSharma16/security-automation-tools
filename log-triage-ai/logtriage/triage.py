"""Alert triage: turns raw detector output into an analyst-ready report.

Two triage backends are provided behind the same `TriageClient` protocol:

- `HeuristicTriageClient` — deterministic, offline, no API key required.
  Used as the default so the tool is fully runnable without any setup.
- `AnthropicTriageClient` — sends the alert set to Claude and asks for a
  structured incident summary with severity, an executive summary, and
  recommended response actions.

`TriageEngine` ties parsing, detection, and triage together.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Literal, Protocol

from pydantic import BaseModel

from .detectors import run_detectors
from .models import Alert, LogEvent
from .parser import parse_log

Severity = Literal["low", "medium", "high", "critical"]

_SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_DEFAULT_MODEL = "claude-opus-4-8"

_SYSTEM_PROMPT = (
    "You are a SOC tier-2 analyst triaging alerts produced by an automated "
    "log detection pipeline. For each alert, write a short analyst note "
    "explaining the risk in plain language and assign a severity. Then write "
    "a two-to-three sentence executive summary of the incident as a whole, "
    "an overall severity, and a prioritized list of concrete remediation "
    "steps (e.g. block an IP, rotate credentials, isolate a host). Be "
    "concrete and specific to the alerts given — do not give generic advice "
    "that ignores the evidence."
)


class AlertTriageResult(BaseModel):
    alert_id: str
    analyst_notes: str
    severity: Severity


class TriageReport(BaseModel):
    overall_severity: Severity
    executive_summary: str
    recommended_actions: list[str]
    alerts: list[AlertTriageResult]


class TriageClient(Protocol):
    def triage(self, alerts: list[Alert]) -> TriageReport: ...


class HeuristicTriageClient:
    """Deterministic, offline triage — no LLM call, no API key needed.

    Used as the default backend and as the fallback when no Anthropic API
    key is configured, so the CLI is always runnable out of the box.
    """

    def triage(self, alerts: list[Alert]) -> TriageReport:
        if not alerts:
            return TriageReport(
                overall_severity="low",
                executive_summary="No security-relevant events were detected in this log.",
                recommended_actions=[],
                alerts=[],
            )

        results = [
            AlertTriageResult(
                alert_id=alert.id,
                analyst_notes=alert.description,
                severity=alert.severity,  # type: ignore[arg-type]
            )
            for alert in alerts
        ]
        overall = max((a.severity for a in results), key=lambda s: _SEVERITY_RANK[s])

        actions = []
        seen_types = {alert.type for alert in alerts}
        if "brute_force" in seen_types or "credential_compromise" in seen_types:
            offending_ips = sorted({a.source_ip for a in alerts if a.source_ip})
            for ip in offending_ips:
                actions.append(f"Block or rate-limit source IP {ip} at the firewall/WAF.")
        if "credential_compromise" in seen_types:
            actions.append("Force a password reset for any accounts that logged in successfully "
                            "after a failed-login burst, and review their session activity.")
        if "privilege_escalation" in seen_types:
            actions.append("Review sudoers and recently modified SUID binaries; revert "
                            "unauthorized privilege changes.")
        actions.append("Preserve the raw log source for this window in case further "
                        "investigation or legal hold is required.")

        summary = (
            f"{len(alerts)} alert(s) detected, highest severity '{overall}'. "
            f"Categories: {', '.join(sorted(seen_types))}."
        )

        return TriageReport(
            overall_severity=overall,  # type: ignore[arg-type]
            executive_summary=summary,
            recommended_actions=actions,
            alerts=results,
        )


class AnthropicTriageClient:
    """Sends the alert set to Claude for narrative triage and structured output."""

    def __init__(self, model: str = _DEFAULT_MODEL):
        import anthropic  # local import: keep this an optional dependency path

        self.model = model
        self._client = anthropic.Anthropic()

    def triage(self, alerts: list[Alert]) -> TriageReport:
        if not alerts:
            return HeuristicTriageClient().triage(alerts)

        alert_payload = [
            {
                "id": alert.id,
                "type": alert.type,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "mitre_technique": alert.mitre_technique,
                "source_ip": alert.source_ip,
                "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
                "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
                "evidence": alert.related_raw,
            }
            for alert in alerts
        ]

        response = self._client.messages.parse(
            model=self.model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Triage the following detector alerts:\n\n"
                        + json.dumps(alert_payload, indent=2)
                    ),
                }
            ],
            output_format=TriageReport,
        )
        return response.parsed_output


class TriageEngine:
    """End-to-end pipeline: parse log lines -> run detectors -> triage alerts."""

    def __init__(self, triage_client: TriageClient | None = None, year: int | None = None):
        self.triage_client = triage_client or self._default_client()
        self.year = year

    @staticmethod
    def _default_client() -> TriageClient:
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                return AnthropicTriageClient()
            except Exception:
                return HeuristicTriageClient()
        return HeuristicTriageClient()

    def analyze(self, lines: list[str]) -> tuple[list[LogEvent], list[Alert], TriageReport]:
        year = self.year or _current_year()
        events = parse_log(lines, year=year)
        alerts = run_detectors(events)
        report = self.triage_client.triage(alerts)
        return events, alerts, report


def _current_year() -> int:
    # auth.log timestamps omit the year; default to the current one unless
    # the caller supplies an explicit --year for historical log files.
    import datetime

    return datetime.datetime.now().year


def alert_to_dict(alert: Alert) -> dict:
    data = asdict(alert)
    for key in ("first_seen", "last_seen"):
        if data.get(key) is not None:
            data[key] = data[key].isoformat()
    return data
