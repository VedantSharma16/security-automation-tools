"""Wires parsing, rule matching, and summarization into one call."""

from __future__ import annotations

import json
from pathlib import Path

from .models import TriageReport
from .parser import parse_file
from .rules import RuleEngine
from .summarizer import Summarizer


def run_pipeline(
    logfile: str | Path,
    engine: RuleEngine,
    summarizer: Summarizer,
) -> TriageReport:
    events = parse_file(logfile)
    findings = engine.scan(events)
    return summarizer.summarize(findings, total_events=len(events))


def report_to_dict(report: TriageReport) -> dict:
    return {
        "generated_by": report.generated_by,
        "stats": report.stats,
        "summary": report.summary,
        "findings": [
            {
                "rule_id": f.rule.id,
                "rule_name": f.rule.name,
                "severity": f.severity.name,
                "mitre_technique": f.rule.mitre_technique,
                "line_number": f.event.line_number,
                "line": f.event.raw,
            }
            for f in report.findings
        ],
    }


def report_to_json(report: TriageReport) -> str:
    return json.dumps(report_to_dict(report), indent=2)
