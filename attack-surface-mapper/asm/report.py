"""Assemble scored findings into a JSON-serializable report and render it."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .nmap_parser import Host
from .scoring import HostRisk, ScoredMatch, rank_hosts, severity_for_score


def build_report(scan_path: str | Path, hosts: list[Host], scored: list[ScoredMatch]) -> dict:
    host_risks = rank_hosts(scored)
    overall_score = max((r.score for r in host_risks), default=0.0)

    findings = [
        {
            "host": sm.match.host,
            "hostname": sm.match.hostname,
            "port": sm.match.port_id,
            "protocol": sm.match.protocol,
            "service": sm.match.service_label,
            "rule_id": sm.match.rule.rule_id,
            "rule_type": sm.match.rule.rule_type,
            "title": sm.match.rule.title,
            "description": sm.match.rule.description,
            "cvss": sm.match.rule.cvss,
            "exploit_available": sm.match.rule.exploit_available,
            "reference": sm.match.rule.reference,
            "confidence": sm.match.confidence,
            "score": sm.score,
            "severity": sm.severity,
        }
        for sm in scored
    ]

    return {
        "scan_file": str(scan_path),
        "generated_at": None,  # filled by CLI at output time to keep this function pure/testable
        "hosts_scanned": len(hosts),
        "open_ports_scanned": sum(len(h.open_ports()) for h in hosts),
        "summary": {
            "total_findings": len(findings),
            "overall_score": overall_score,
            "overall_severity": severity_for_score(overall_score),
            "hosts_at_risk": len(host_risks),
        },
        "host_risk_ranking": [
            {
                "host": r.host,
                "hostname": r.hostname,
                "score": r.score,
                "severity": r.severity,
                "finding_count": r.finding_count,
            }
            for r in host_risks
        ],
        "findings": findings,
    }


def stamp_generated_at(report: dict) -> dict:
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    return report


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Attack Surface Report",
        "",
        f"- Scan file: `{report['scan_file']}`",
        f"- Generated: {report.get('generated_at') or 'n/a'}",
        f"- Hosts scanned: {report['hosts_scanned']}",
        f"- Open ports scanned: {report['open_ports_scanned']}",
        f"- Overall risk: **{summary['overall_severity'].upper()}** "
        f"({summary['overall_score']}/100)",
        f"- Total findings: {summary['total_findings']}",
        "",
    ]

    if not report["findings"]:
        lines.append("No known CVE or insecure-protocol matches were found in the local rule "
                      "database. This does not mean the target is unaffected -- only that "
                      "nothing in `data/cve_db.json` matched the fingerprinted services.")
        return "\n".join(lines)

    lines.append("## Host Risk Ranking")
    lines.append("")
    lines.append("| Host | Hostname | Score | Severity | Findings |")
    lines.append("|---|---|---|---|---|")
    for r in report["host_risk_ranking"]:
        lines.append(
            f"| {r['host']} | {r['hostname'] or '-'} | {r['score']} | "
            f"{r['severity'].upper()} | {r['finding_count']} |"
        )
    lines.append("")

    lines.append("## Findings (highest priority first)")
    lines.append("")
    for f in report["findings"]:
        confidence_note = "" if f["confidence"] == "confirmed" else " _(unconfirmed: version unverified)_"
        exploit_note = " -- known exploit available" if f["exploit_available"] else ""
        lines.append(
            f"### [{f['severity'].upper()}] {f['title']} -- {f['host']}:{f['port']}/{f['protocol']}"
        )
        lines.append("")
        lines.append(
            f"- Service: {f['service']}\n"
            f"- Rule: `{f['rule_id']}` ({f['rule_type']}), CVSS {f['cvss']}{exploit_note}\n"
            f"- Score: {f['score']}/100{confidence_note}\n"
            f"- {f['description']}\n"
            f"- Reference: {f['reference']}"
        )
        lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)
