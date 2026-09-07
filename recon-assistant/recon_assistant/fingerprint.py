"""Passive, banner-based service identification and risk flags.

Everything here is read-only: it looks at which port responded and what (if
anything) the service said first. It never attempts authentication, sends
exploit payloads, or brute-forces credentials — that's the boundary between
recon and active exploitation, and this tool stays on the recon side of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Finding:
    type: str
    severity: str
    port: int
    title: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "port": self.port,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


EXPOSED_DATABASE_PORTS = {
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

_OPENSSH_VERSION_RE = re.compile(r"OpenSSH_(\d+)\.(\d+)")


def _check_telnet(port: int, banner: str) -> Finding | None:
    if port == 23 or "telnet" in banner.lower():
        return Finding(
            type="cleartext_protocol",
            severity="high",
            port=port,
            title="Telnet service exposed",
            detail=f"Port {port} appears to be running Telnet.",
            recommendation="Telnet transmits credentials and session data in "
            "cleartext. Disable it and use SSH instead.",
        )
    return None


def _check_ftp(port: int, banner: str) -> Finding | None:
    looks_like_ftp = banner.startswith("220") and "FTP" in banner.upper()
    if port == 21 or looks_like_ftp:
        return Finding(
            type="cleartext_protocol",
            severity="medium",
            port=port,
            title="FTP service exposed",
            detail=f"Port {port} appears to be running FTP.",
            recommendation="FTP transmits credentials in cleartext. Prefer "
            "SFTP/FTPS, and manually verify anonymous login is disabled.",
        )
    return None


def _check_outdated_openssh(port: int, banner: str) -> Finding | None:
    match = _OPENSSH_VERSION_RE.search(banner)
    if not match:
        return None
    version = (int(match.group(1)), int(match.group(2)))
    if version < (7, 4):
        return Finding(
            type="outdated_service",
            severity="medium",
            port=port,
            title="Outdated OpenSSH version banner",
            detail=f"Port {port} banner reports {match.group(0)}.",
            recommendation="Verify the patch level against known OpenSSH "
            "CVEs for this release line and upgrade if out of support.",
        )
    return None


def _check_exposed_database(port: int, banner: str) -> Finding | None:
    name = EXPOSED_DATABASE_PORTS.get(port)
    if not name:
        return None
    return Finding(
        type="exposed_database",
        severity="high",
        port=port,
        title=f"{name} reachable on this network path",
        detail=f"Port {port} ({name}) accepted a connection.",
        recommendation=f"Confirm {name} exposure on this network path is "
        "intentional; restrict via firewall/security-group rules and require "
        "authentication if not already enforced.",
    )


def _check_smb(port: int, banner: str) -> Finding | None:
    if port == 445:
        return Finding(
            type="exposed_admin_surface",
            severity="high",
            port=port,
            title="SMB exposed",
            detail="Port 445 (SMB) accepted a connection.",
            recommendation="SMB is a common lateral-movement and ransomware "
            "propagation vector. Restrict it to trusted network segments.",
        )
    return None


def _check_rdp(port: int, banner: str) -> Finding | None:
    if port == 3389:
        return Finding(
            type="exposed_admin_surface",
            severity="medium",
            port=port,
            title="RDP exposed",
            detail="Port 3389 (RDP) accepted a connection.",
            recommendation="Ensure Network Level Authentication is enabled "
            "and restrict source IPs (VPN/bastion) rather than exposing RDP "
            "broadly.",
        )
    return None


_CHECKS = (
    _check_telnet,
    _check_ftp,
    _check_outdated_openssh,
    _check_exposed_database,
    _check_smb,
    _check_rdp,
)


def fingerprint_port(port: int, banner: str) -> list[Finding]:
    """Run all passive checks against one open port and its (possibly empty) banner."""
    findings = []
    for check in _CHECKS:
        result = check(port, banner)
        if result is not None:
            findings.append(result)
    return findings
