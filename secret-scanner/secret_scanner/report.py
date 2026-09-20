"""Render findings as human-readable text, JSON, or SARIF (for GitHub code scanning)."""

from __future__ import annotations

import json
from collections import Counter

from secret_scanner.scanner import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file_path, f.line_number))


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {severity: counts.get(severity, 0) for severity in SEVERITY_ORDER}


def format_text(findings: list[Finding]) -> str:
    if not findings:
        return "No secrets found.\n"

    findings = sort_findings(findings)
    lines = [f"Found {len(findings)} potential secret(s):", ""]
    for finding in findings:
        location = f"{finding.file_path}:{finding.line_number}"
        origin = f" (commit {finding.commit[:8]} by {finding.author}, {finding.date})" if finding.commit else ""
        lines.append(f"[{finding.severity.upper()}] {finding.rule_id} - {finding.description}")
        lines.append(f"  {location}{origin}")
        lines.append(f"  {finding.redacted_line.strip()}")
        lines.append(f"  fingerprint: {finding.fingerprint}")
        lines.append("")

    summary = summarize(findings)
    lines.append("Summary: " + ", ".join(f"{count} {sev}" for sev, count in summary.items() if count))
    return "\n".join(lines) + "\n"


def format_json(findings: list[Finding]) -> str:
    findings = sort_findings(findings)
    payload = {
        "summary": summarize(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "description": f.description,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "secret": f.redacted_secret,
                "line": f.redacted_line,
                "fingerprint": f.fingerprint,
                "commit": f.commit,
                "author": f.author,
                "date": f.date,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def format_sarif(findings: list[Finding]) -> str:
    findings = sort_findings(findings)
    rule_ids = sorted({f.rule_id for f in findings})
    rule_index = {rule_id: i for i, rule_id in enumerate(rule_ids)}
    descriptions = {f.rule_id: f.description for f in findings}

    sarif_rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": descriptions[rule_id]},
        }
        for rule_id in rule_ids
    ]

    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{finding.description} (fingerprint {finding.fingerprint})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"startLine": max(finding.line_number, 1)},
                        }
                    }
                ],
                "partialFingerprints": {"secretScannerFingerprint": finding.fingerprint},
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-scanner",
                        "informationUri": "https://github.com/vedantsharma16/security-automation-tools",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
}
