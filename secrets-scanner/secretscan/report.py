"""Turning a list of Findings into console output, JSON, and SARIF reports.

SARIF (Static Analysis Results Interchange Format) is what GitHub Code
Scanning, Azure DevOps, and most CI security dashboards expect — emitting it
is what turns this from a standalone CLI into something that plugs into a
real pipeline (`upload-sarif` in a GitHub Actions workflow, for example).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .rules import SEVERITY_RANK

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

_SEVERITY_COLOR = {
    "low": "\033[36m",       # cyan
    "medium": "\033[33m",    # yellow
    "high": "\033[31m",      # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"

# SARIF severity levels are coarser than ours; map down to them.
_SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}


def highest_severity(findings: list):
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def build_report(findings: list, scanned_paths: list, scanned_at: float | None = None) -> dict:
    scanned_at = scanned_at if scanned_at is not None else datetime.now(tz=timezone.utc).timestamp()
    findings_sorted = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], _CONFIDENCE_RANK[f.confidence]),
        reverse=True,
    )
    by_severity = {sev: 0 for sev in SEVERITY_RANK}
    for f in findings:
        by_severity[f.severity] += 1

    return {
        "scanned_at": datetime.fromtimestamp(scanned_at, tz=timezone.utc).isoformat(),
        "scanned_paths": scanned_paths,
        "finding_count": len(findings),
        "highest_severity": highest_severity(findings),
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in findings_sorted],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    filtered = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def render_console(report: dict, use_color: bool = True) -> str:
    lines = [f"secretscan — scan at {report['scanned_at']}"]
    lines.append(f"Paths scanned     : {', '.join(report['scanned_paths'])}")
    lines.append(f"Findings          : {report['finding_count']}")
    if report["highest_severity"]:
        lines.append(f"Highest severity  : {report['highest_severity']}")
    lines.append("")

    for f in report["findings"]:
        color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
        reset = _RESET if use_color else ""
        location = f["file_path"]
        if f.get("line"):
            location += f":{f['line']}"
        header = f"[{f['severity'].upper()}] {f['rule_id']}  ({f['confidence']} confidence)"
        lines.append(f"{color}{header}{reset}")
        lines.append(f"  {location}" + (f"  @ {f['commit']}" if f.get("commit") else ""))
        lines.append(f"  value    : {f['redacted_secret']}")
        if f.get("context_key"):
            lines.append(f"  variable : {f['context_key']}")
        lines.append(f"  why      : {f['description']}")
        if f.get("triage_reason"):
            lines.append(f"  triage   : {f['triage_reason']}")
        lines.append("")

    if not report["findings"]:
        lines.append("No secrets found. \\o/")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")


def build_sarif(report: dict, tool_version: str = "0.1.0") -> dict:
    rule_ids = sorted({f["rule_id"] for f in report["findings"]})
    rules_meta = {rid: next(f for f in report["findings"] if f["rule_id"] == rid) for rid in rule_ids}

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secretscan",
                        "version": tool_version,
                        "informationUri": "https://github.com/",
                        "rules": [
                            {
                                "id": rid,
                                "shortDescription": {"text": rules_meta[rid]["description"] or rid},
                                "properties": {"category": rules_meta[rid]["category"]},
                            }
                            for rid in rule_ids
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f["rule_id"],
                        "level": _SARIF_LEVEL.get(f["severity"], "warning"),
                        "message": {
                            "text": f"{f['description']} (redacted: {f['redacted_secret']}, "
                            f"confidence: {f['confidence']})"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f["file_path"]},
                                    "region": {"startLine": f["line"] or 1},
                                }
                            }
                        ],
                        "partialFingerprints": {"secretscanFingerprint": f["fingerprint"]},
                    }
                    for f in report["findings"]
                ],
            }
        ],
    }


def write_sarif(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(report), fh, indent=2)
        fh.write("\n")
