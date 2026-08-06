"""Runs a recon plan (static or agentic) against a target and assembles the
findings into a scored ReconReport.
"""
from __future__ import annotations

from . import planner
from . import report as report_module
from . import scoring
from .models import ReconReport
from .tools import build_registry


def run(target: str, agentic: bool = False, client=None) -> ReconReport:
    registry = build_registry(target)
    narrative = ""

    if agentic:
        tool_results, narrative = planner.run_agentic(registry, target, client=client)
        if not tool_results:
            tool_results = planner.run_static(registry)
    else:
        tool_results = planner.run_static(registry)

    findings = [f for result in tool_results for f in result.findings]
    score = scoring.score_findings(findings)
    grade = scoring.grade_for_score(score)

    rep = ReconReport(target=target, tool_results=tool_results, score=score, grade=grade, narrative=narrative)
    if not rep.narrative:
        rep.narrative = report_module.offline_narrative(rep)
    return rep
