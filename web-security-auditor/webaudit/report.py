"""Aggregating check results into a scored report (console + JSON)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .models import CheckResult, SEVERITY_WEIGHTS

_GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D")]
_STATUS_ORDER = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
_STATUS_COLOR = {"fail": "\033[31m", "warn": "\033[33m", "pass": "\033[32m", "info": "\033[36m"}
_RESET = "\033[0m"


def compute_score(results: list[CheckResult]) -> int:
    deductions = sum(
        SEVERITY_WEIGHTS[r.severity] for r in results if r.status in ("fail", "warn")
    )
    return max(0, 100 - deductions)


def grade_for_score(score: int) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def build_report(
    target: str, results: list[CheckResult], scanned_at: Optional[datetime] = None
) -> dict:
    scanned_at = scanned_at or datetime.now(timezone.utc)
    score = compute_score(results)

    summary = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for r in results:
        summary[r.status] = summary.get(r.status, 0) + 1

    ordered = sorted(
        results, key=lambda r: (_STATUS_ORDER[r.status], -SEVERITY_WEIGHTS[r.severity])
    )

    return {
        "target": target,
        "scanned_at": scanned_at.isoformat(),
        "score": score,
        "grade": grade_for_score(score),
        "summary": summary,
        "checks": [
            {
                "id": r.id,
                "category": r.category,
                "status": r.status,
                "severity": r.severity,
                "title": r.title,
                "detail": r.detail,
                "remediation": r.remediation,
            }
            for r in ordered
        ],
    }


def render_console(report: dict, use_color: bool = True) -> str:
    lines = [
        f"Web Security Auditor — {report['target']}",
        f"Scanned at : {report['scanned_at']}",
        f"Score      : {report['score']}/100 (grade {report['grade']})",
    ]
    s = report["summary"]
    lines.append(
        f"Checks     : {s.get('pass', 0)} pass / {s.get('warn', 0)} warn / "
        f"{s.get('fail', 0)} fail / {s.get('info', 0)} info"
    )
    lines.append("")

    for c in report["checks"]:
        color = _STATUS_COLOR.get(c["status"], "") if use_color else ""
        reset = _RESET if use_color else ""
        lines.append(f"{color}[{c['status'].upper():4}]{reset} {c['title']} — {c['detail']}")
        if c["remediation"]:
            lines.append(f"       fix: {c['remediation']}")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
