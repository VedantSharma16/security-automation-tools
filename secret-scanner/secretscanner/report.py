"""Turning scan results into console, JSON, and SARIF output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .rules import SEVERITY_RANK

_SEVERITY_COLOR = {
    "low": "\033[36m",  # cyan
    "medium": "\033[33m",  # yellow
    "high": "\033[31m",  # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"

# SARIF's severity model is a 3-level "level", not our 4-level "severity".
_SARIF_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def highest_severity(findings: list):
    if not findings:
        return None
    return max((f.rule.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def build_report(findings: list, scanned_path: str, files_scanned: int, suppressed_by_baseline: int = 0) -> dict:
    findings_sorted = sorted(
        findings, key=lambda f: (SEVERITY_RANK[f.rule.severity], f.file, f.line_number), reverse=True
    )
    return {
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "scanned_path": scanned_path,
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "suppressed_by_baseline": suppressed_by_baseline,
        "highest_severity": highest_severity(findings),
        "findings": [
            {
                "fingerprint": f.fingerprint(),
                "rule_id": f.rule.id,
                "severity": f.rule.severity,
                "category": f.rule.category,
                "description": f.rule.description,
                "file": f.file,
                "line": f.line_number,
                "secret": f.redacted_secret(),
            }
            for f in findings_sorted
        ],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    filtered = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def render_console(report: dict, use_color: bool = True) -> str:
    lines = []
    lines.append(f"Secret Scanner — scan of {report['scanned_path']} at {report['scanned_at']}")
    lines.append(f"Files scanned : {report['files_scanned']}")
    lines.append(f"Findings      : {report['finding_count']}")
    if report["suppressed_by_baseline"]:
        lines.append(f"Suppressed by baseline: {report['suppressed_by_baseline']}")

    if not report["findings"]:
        lines.append("No secrets found. ✅")
    else:
        lines.append("")
        for f in report["findings"]:
            color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
            reset = _RESET if use_color else ""
            lines.append(
                f"{color}[{f['severity'].upper():8}]{reset} {f['rule_id']} ({f['category']})"
            )
            lines.append(f"           {f['file']}:{f['line']}  secret={f['secret']}")
            if f["description"]:
                lines.append(f"           {f['description']}")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def build_sarif(report: dict) -> dict:
    """Build a minimal SARIF 2.1.0 log, suitable for GitHub code scanning."""
    rule_ids = sorted({f["rule_id"] for f in report["findings"]})
    rule_lookup = {f["rule_id"]: f for f in report["findings"]}

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-scanner",
                        "informationUri": "https://github.com/",
                        "rules": [
                            {
                                "id": rid,
                                "shortDescription": {"text": rule_lookup[rid]["description"] or rid},
                                "properties": {"category": rule_lookup[rid]["category"]},
                            }
                            for rid in rule_ids
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f["rule_id"],
                        "level": _SARIF_LEVEL[f["severity"]],
                        "message": {"text": f"{f['description']} (secret={f['secret']})"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f["file"]},
                                    "region": {"startLine": f["line"]},
                                }
                            }
                        ],
                        "partialFingerprints": {"secretScannerFingerprint": f["fingerprint"]},
                    }
                    for f in report["findings"]
                ],
            }
        ],
    }


def write_sarif(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(report), fh, indent=2)
