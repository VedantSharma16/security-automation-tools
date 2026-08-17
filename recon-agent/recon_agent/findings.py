"""Turn raw recon tool output into structured, severity-ranked findings.

Kept deterministic and independent of whether the run was agent-driven or
the offline fixed pipeline, so the same rules apply — and are testable — in
both modes.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1"}


@dataclass
class Finding:
    severity: str
    category: str
    description: str

    def to_dict(self) -> dict:
        return {"severity": self.severity, "category": self.category, "description": self.description}


def derive_findings(tool_results: dict[str, list[dict]]) -> list[Finding]:
    """Build a severity-sorted finding list from every tool result gathered so far."""
    findings: list[Finding] = []

    for result in tool_results.get("subdomain_enum", []):
        for entry in result.get("discovered", []):
            if entry.get("sensitive"):
                findings.append(Finding(
                    "medium",
                    "exposed-subdomain",
                    f"Sensitive-sounding subdomain '{entry['subdomain']}' resolves publicly to "
                    f"{', '.join(entry['addresses'])}.",
                ))

    for result in tool_results.get("http_probe", []):
        if not result.get("reachable"):
            continue
        missing = result.get("missing_security_headers", [])
        if missing:
            findings.append(Finding(
                "medium" if len(missing) >= 3 else "low",
                "missing-security-headers",
                f"{result['host']} is missing {len(missing)} recommended security header(s): "
                f"{', '.join(missing)}.",
            ))

    for result in tool_results.get("tls_probe", []):
        if not result.get("reachable"):
            continue
        days = result.get("days_until_expiry")
        if days is not None:
            if days < 0:
                findings.append(Finding(
                    "critical", "expired-certificate",
                    f"TLS certificate for {result['host']} expired {abs(days)} day(s) ago.",
                ))
            elif days < 14:
                findings.append(Finding(
                    "high", "expiring-certificate",
                    f"TLS certificate for {result['host']} expires in {days} day(s).",
                ))
            elif days < 30:
                findings.append(Finding(
                    "medium", "expiring-certificate",
                    f"TLS certificate for {result['host']} expires in {days} day(s).",
                ))
        if result.get("protocol") in WEAK_PROTOCOLS:
            findings.append(Finding(
                "high", "weak-tls-protocol",
                f"{result['host']} negotiated outdated protocol {result['protocol']}.",
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return findings


def overall_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity
