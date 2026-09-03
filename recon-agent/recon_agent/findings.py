"""Turn raw recon data (open ports, HTTP/TLS fingerprints) into risk findings."""

from __future__ import annotations

from dataclasses import dataclass

from .http_fingerprint import HttpFingerprint
from .port_scan import PortResult

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# port -> (severity, rationale)
RISKY_PORTS = {
    21: ("high", "FTP often transmits credentials in plaintext."),
    23: ("critical", "Telnet transmits all traffic, including credentials, unencrypted."),
    139: ("medium", "NetBIOS session service; historically a common lateral-movement vector."),
    445: ("medium", "SMB exposed to the network; check for missing patches and open/writable shares."),
    3389: ("high", "RDP exposed directly to the network is a top initial-access vector; should sit behind a VPN/bastion."),
    5432: ("medium", "PostgreSQL exposed; confirm authentication is enforced and it isn't reachable from the internet."),
    6379: ("critical", "Redis has no authentication by default; an exposed instance is a common ransomware entry point."),
    9200: ("high", "Elasticsearch exposed without a reverse proxy has repeatedly led to mass data-exposure incidents."),
    27017: ("high", "MongoDB exposed without authentication is one of the most common causes of data-breach disclosures."),
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
]

SENSITIVE_TITLE_KEYWORDS = [
    "admin", "login", "dashboard", "panel", "jenkins", "phpmyadmin", "grafana", "kibana",
]


@dataclass
class Finding:
    severity: str
    category: str
    target: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "target": self.target,
            "detail": self.detail,
        }


def _rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def _evaluate_ports(host: str, open_ports: list[PortResult]) -> list[Finding]:
    findings = []
    for result in open_ports:
        if result.port in RISKY_PORTS:
            severity, rationale = RISKY_PORTS[result.port]
            findings.append(
                Finding(severity, "exposed-service", f"{host}:{result.port}", f"{result.service} open. {rationale}")
            )
    return findings


def _evaluate_http(host: str, fingerprints: list[HttpFingerprint]) -> list[Finding]:
    findings = []
    for fp in fingerprints:
        if fp.error:
            continue
        target = f"{host}:{fp.port}"

        if fp.title and any(keyword in fp.title.lower() for keyword in SENSITIVE_TITLE_KEYWORDS):
            severity = "medium" if fp.scheme == "https" else "high"
            findings.append(
                Finding(
                    severity,
                    "sensitive-endpoint",
                    target,
                    f"Page title '{fp.title}' suggests an admin/management interface; confirm it "
                    "requires strong authentication and isn't reachable from the open internet.",
                )
            )

        if fp.scheme == "https":
            missing = [h for h in SECURITY_HEADERS if h not in fp.headers]
            if missing:
                findings.append(
                    Finding("low", "missing-security-headers", target, f"Missing headers: {', '.join(missing)}.")
                )
            if fp.tls_days_remaining is not None:
                if fp.tls_days_remaining < 0:
                    findings.append(
                        Finding(
                            "critical",
                            "expired-certificate",
                            target,
                            f"TLS certificate expired {abs(fp.tls_days_remaining)} day(s) ago.",
                        )
                    )
                elif fp.tls_days_remaining < 30:
                    findings.append(
                        Finding(
                            "medium",
                            "expiring-certificate",
                            target,
                            f"TLS certificate expires in {fp.tls_days_remaining} day(s).",
                        )
                    )
            elif fp.tls_error:
                findings.append(
                    Finding("medium", "unverifiable-certificate", target, f"TLS certificate could not be verified: {fp.tls_error}")
                )
        elif fp.status is not None:
            findings.append(
                Finding("low", "cleartext-http", target, "Service responds over plaintext HTTP; consider requiring HTTPS.")
            )

    return findings


def evaluate(host: str, open_ports: list[PortResult], http_fingerprints: list[HttpFingerprint]) -> list[Finding]:
    """Build a severity-sorted (highest first) list of findings from recon data."""
    findings = _evaluate_ports(host, open_ports) + _evaluate_http(host, http_fingerprints)
    findings.sort(key=lambda f: _rank(f.severity), reverse=True)
    return findings


def overall_risk(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max((f.severity for f in findings), key=_rank)
