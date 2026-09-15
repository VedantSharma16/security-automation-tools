"""Aggregate a ReconRun's raw tool outputs into scored, human-readable findings."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from recon_agent.agent import ReconRun
from recon_agent.http_recon import audit_security_headers

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

with open(os.path.join(_DATA_DIR, "port_risk.json"), encoding="utf-8") as _fh:
    PORT_RISK: dict[str, dict] = json.load(_fh)

_SEVERITY_WEIGHT = {"info": 0, "low": 2, "medium": 5, "high": 10, "critical": 18}
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_TLS_EXPIRY_WARNING_DAYS = 30


@dataclass(frozen=True)
class Finding:
    category: str
    title: str
    severity: str
    detail: str

    def to_dict(self) -> dict:
        return {"category": self.category, "title": self.title, "severity": self.severity, "detail": self.detail}


@dataclass
class ReconReport:
    target: str
    findings: list[Finding]
    risk_score: int
    overall_severity: str
    steps_taken: list[str]
    planner_live: bool
    narrative: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "risk_score": self.risk_score,
            "overall_severity": self.overall_severity,
            "steps_taken": self.steps_taken,
            "planner_live": self.planner_live,
            "findings": [f.to_dict() for f in self.findings],
            "narrative": self.narrative,
        }


def _findings_from_dns(data: dict) -> list[Finding]:
    if data.get("resolved"):
        return []
    return [Finding("dns", "Target hostname does not resolve", "high", data.get("error") or "DNS resolution failed.")]


def _findings_from_subdomains(data: dict) -> list[Finding]:
    count = data.get("count", 0)
    if count == 0:
        return []
    names = ", ".join(s["subdomain"] for s in data["found"])
    return [Finding("attack-surface", f"{count} additional subdomain(s) discovered", "low", f"Expands attack surface: {names}")]


def _findings_from_ports(data: dict) -> list[Finding]:
    findings = []
    for entry in data.get("open_ports", []):
        port = str(entry["port"])
        risk = PORT_RISK.get(port, {"service": "unknown", "severity": "medium", "note": "Unrecognized service on an open port; investigate manually."})
        detail = risk["note"]
        if entry.get("banner"):
            detail += f" Banner: {entry['banner'][:120]!r}"
        findings.append(Finding("open-port", f"Port {port} ({risk['service']}) open", risk["severity"], detail))
    return findings


def _findings_from_http(data: dict) -> list[Finding]:
    if data.get("error"):
        return [Finding("http", "HTTP(S) request failed", "info", data["error"])]
    findings = []
    for missing in audit_security_headers(data.get("headers", {})):
        findings.append(Finding("http-header", f"Missing {missing.header} header", missing.severity, missing.description))
    server = data.get("headers", {}).get("server")
    if server:
        findings.append(Finding("http-header", "Server header discloses software/version", "low", f"Server: {server}"))
    return findings


def _findings_from_tls(data: dict) -> list[Finding]:
    if not data.get("fetched"):
        return [Finding("tls", "TLS certificate could not be retrieved", "info", data.get("error") or "unknown error")]
    days = data.get("days_remaining")
    if days is None:
        return []
    if days < 0:
        return [Finding("tls", "TLS certificate has expired", "critical", f"Expired {-days} day(s) ago (notAfter={data['not_after']}).")]
    if days <= _TLS_EXPIRY_WARNING_DAYS:
        return [Finding("tls", "TLS certificate expiring soon", "high", f"{days} day(s) remaining (notAfter={data['not_after']}).")]
    return []


_STEP_HANDLERS = {
    "dns_lookup": _findings_from_dns,
    "subdomain_enum": _findings_from_subdomains,
    "port_scan": _findings_from_ports,
    "http_headers": _findings_from_http,
    "tls_cert": _findings_from_tls,
}


def _score(findings: list[Finding]) -> tuple[int, str]:
    score = min(100, sum(_SEVERITY_WEIGHT[f.severity] for f in findings))
    highest = "info"
    for f in findings:
        if _SEVERITY_ORDER.index(f.severity) > _SEVERITY_ORDER.index(highest):
            highest = f.severity
    return score, highest


def build_report(run: ReconRun, narrative: str = "") -> ReconReport:
    findings: list[Finding] = []
    for step in run.session.steps:
        handler = _STEP_HANDLERS.get(step.tool)
        if handler:
            findings.extend(handler(step.data))

    score, highest = _score(findings)
    return ReconReport(
        target=run.session.target,
        findings=findings,
        risk_score=score,
        overall_severity=highest,
        steps_taken=[s.tool for s in run.session.steps],
        planner_live=run.planner_live,
        narrative=narrative,
    )
