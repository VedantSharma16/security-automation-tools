"""Turns a finished ``AgentRun`` into structured findings plus a report."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from .llm_client import Narrator
from .severity import WEIGHTS

SENSITIVE_ROBOTS_KEYWORDS = [
    "admin", "backup", ".git", "config", "wp-admin", "secret", "private", "api-key", "database", "db-",
]
OUTDATED_TLS_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
COMMON_WEB_PORTS = {80, 443}
HIGH_RISK_PORTS = {21, 23, 3389, 3306}
CERT_EXPIRY_WARNING_DAYS = 30


@dataclass
class Finding:
    category: str
    severity: str
    summary: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReconReport:
    target: str
    severity: str
    findings: list[Finding]
    transcript_summary: list[str]
    narrative: str
    llm_backed: bool
    finished_reason: str
    planner: str

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
            "transcript_summary": self.transcript_summary,
            "narrative": self.narrative,
            "llm_backed": self.llm_backed,
            "finished_reason": self.finished_reason,
            "planner": self.planner,
        }


def _target_port(target: str) -> int:
    parsed = urlparse(target)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _cert_days_left(cert) -> int | None:
    if not cert or "notAfter" not in cert:
        return None
    try:
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (expiry - datetime.now(timezone.utc)).days


def collect_findings(run) -> list[Finding]:
    findings: list[Finding] = []
    by_tool = {step.action.tool: step for step in run.steps}

    dns_step = by_tool.get("dns_lookup")
    if dns_step and not dns_step.result.ok:
        findings.append(
            Finding("dns", "low", f"Could not resolve {dns_step.result.data.get('host')}: {dns_step.result.error}")
        )

    headers_step = by_tool.get("fetch_headers")
    if headers_step:
        if not headers_step.result.ok:
            findings.append(
                Finding(
                    "connectivity", "medium",
                    f"Could not fetch {headers_step.result.data.get('url')}: {headers_step.result.error}",
                )
            )
        else:
            headers = {k.lower(): v for k, v in headers_step.result.data.get("headers", {}).items()}
            if "server" in headers:
                findings.append(Finding("info_disclosure", "low", f"Server header discloses software/version: '{headers['server']}'"))
            if "x-powered-by" in headers:
                findings.append(
                    Finding("info_disclosure", "low", f"X-Powered-By header discloses backend technology: '{headers['x-powered-by']}'")
                )

    grade_step = by_tool.get("grade_security_headers")
    if grade_step and grade_step.result.ok:
        for item in grade_step.result.data.get("missing", []):
            findings.append(
                Finding("security_headers", item["severity"], f"Missing or weak '{item['header']}' response header.", item["advice"])
            )

    robots_step = by_tool.get("fetch_robots_txt")
    if robots_step and robots_step.result.ok:
        paths = robots_step.result.data.get("disallowed_paths", [])
        sensitive = [p for p in paths if any(keyword in p.lower() for keyword in SENSITIVE_ROBOTS_KEYWORDS)]
        for path in sensitive:
            findings.append(Finding("recon_disclosure", "medium", f"robots.txt discloses a potentially sensitive path: {path}"))
        if paths and not sensitive:
            findings.append(
                Finding("recon_disclosure", "info", f"robots.txt lists {len(paths)} disallowed path(s); none look obviously sensitive.")
            )

    tls_step = by_tool.get("check_tls")
    if tls_step:
        if not tls_step.result.ok:
            findings.append(
                Finding(
                    "tls", "medium",
                    f"Could not establish a TLS session on {tls_step.result.data.get('host')}:{tls_step.result.data.get('port')}: "
                    f"{tls_step.result.error}",
                )
            )
        else:
            data = tls_step.result.data
            protocol = data.get("protocol")
            if protocol in OUTDATED_TLS_PROTOCOLS:
                findings.append(Finding("tls", "high", f"Server negotiated an outdated TLS protocol: {protocol}."))
            days_left = _cert_days_left(data.get("cert"))
            if days_left is not None and days_left < CERT_EXPIRY_WARNING_DAYS:
                findings.append(Finding("tls", "medium", f"TLS certificate expires in {days_left} day(s)."))

    port_step = by_tool.get("port_scan")
    if port_step and port_step.result.ok:
        expected = COMMON_WEB_PORTS | {_target_port(run.target)}
        for port in port_step.result.data.get("open_ports", []):
            if port in expected:
                continue
            severity = "high" if port in HIGH_RISK_PORTS else "medium"
            findings.append(Finding("exposure", severity, f"Unexpected open port {port} on {port_step.result.data.get('host')}."))

    return findings


def overall_severity(findings: list[Finding]) -> str:
    if not findings:
        return "low"
    score = sum(WEIGHTS.get(f.severity, 0) for f in findings)
    if score >= 40:
        return "critical"
    if score >= 25:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


def build_report(run, narrator: Narrator | None = None) -> ReconReport:
    findings = collect_findings(run)
    severity = overall_severity(findings)
    narrator = narrator or Narrator()
    transcript_summary = [
        f"{step.action.tool}: {'ok' if step.result.ok else 'failed - ' + str(step.result.error)}" for step in run.steps
    ]
    narrative = narrator.narrate(run.target, findings, severity, transcript_summary)
    return ReconReport(
        target=run.target,
        severity=severity,
        findings=findings,
        transcript_summary=transcript_summary,
        narrative=narrative,
        llm_backed=narrator.is_live,
        finished_reason=run.finished_reason,
        planner=run.planner_name,
    )
