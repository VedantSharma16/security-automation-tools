"""Assemble scan results into a JSON- or Markdown-formatted report."""

from __future__ import annotations

import json
from collections import Counter

from .gitscan import GitFinding
from .triage import TriagedFinding


def _finding_entry(triaged: TriagedFinding, git_meta: GitFinding | None = None) -> dict:
    f = triaged.finding
    entry = {
        "source": triaged.source,
        "file": f.file,
        "line": f.line_number,
        "pattern": f.pattern_name,
        "category": f.category,
        "severity": f.severity,
        "detector": f.detector,
        "value": f.redacted_value,
        "likely_false_positive": triaged.likely_false_positive,
        "false_positive_reasons": list(triaged.reasons),
        "remediation": f.remediation,
        "preview": f.line_preview,
    }
    if git_meta is not None:
        entry["commit"] = git_meta.commit
        entry["author"] = git_meta.author
        entry["date"] = git_meta.date
    return entry


def build_report(
    target: str,
    working_tree: list[TriagedFinding],
    history: list[tuple[TriagedFinding, GitFinding]],
    narrative: str,
) -> dict:
    entries = [_finding_entry(t) for t in working_tree]
    entries += [_finding_entry(t, gf) for t, gf in history]

    all_triaged = working_tree + [t for t, _ in history]
    genuine = [t for t in all_triaged if not t.likely_false_positive]
    false_positives = [t for t in all_triaged if t.likely_false_positive]
    by_severity = Counter(t.finding.severity for t in genuine)

    return {
        "target": target,
        "summary": {
            "total_findings": len(all_triaged),
            "likely_genuine": len(genuine),
            "likely_false_positive": len(false_positives),
            "by_severity": {sev: by_severity.get(sev, 0) for sev in ("critical", "high", "medium", "low")},
            "working_tree_findings": len(working_tree),
            "git_history_findings": len(history),
        },
        "findings": entries,
        "narrative": narrative,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        f"# Secret Scan Report: `{report['target']}`",
        "",
        "## Summary",
        f"- Total findings: **{s['total_findings']}** "
        f"({s['likely_genuine']} likely genuine, {s['likely_false_positive']} likely false positive)",
        f"- Working tree: {s['working_tree_findings']} | Git history: {s['git_history_findings']}",
        f"- By severity: critical={s['by_severity']['critical']}, high={s['by_severity']['high']}, "
        f"medium={s['by_severity']['medium']}, low={s['by_severity']['low']}",
        "",
        "## Analyst Narrative",
        report["narrative"],
        "",
        "## Findings",
    ]

    if not report["findings"]:
        lines.append("\nNo findings.")
        return "\n".join(lines)

    for entry in report["findings"]:
        flag = "⚠️ FALSE POSITIVE?" if entry["likely_false_positive"] else ""
        lines.append("")
        lines.append(f"### [{entry['severity'].upper()}] {entry['pattern']} {flag}")
        lines.append(f"- File: `{entry['file']}:{entry['line']}`")
        lines.append(f"- Source: {entry['source']}" + (f" (commit `{entry['commit'][:12]}` by {entry['author']}, {entry['date']})" if "commit" in entry else ""))
        lines.append(f"- Detector: {entry['detector']} | Value: `{entry['value']}`")
        if entry["false_positive_reasons"]:
            lines.append(f"- FP reasons: {', '.join(entry['false_positive_reasons'])}")
        lines.append(f"- Remediation: {entry['remediation']}")
        lines.append(f"- Context: `{entry['preview']}`")

    return "\n".join(lines)
