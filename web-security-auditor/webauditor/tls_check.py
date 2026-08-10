"""TLS/certificate posture checks.

Uses only a standard TLS handshake (no cipher downgrade attempts, no
custom SSL contexts that disable verification) - this reads the
certificate and negotiated protocol a normal client would see.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from .findings import Finding, Severity

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5
EXPIRY_WARNING_DAYS = 30
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    not_after: datetime
    protocol: str
    days_until_expiry: int


def get_certificate_info(hostname: str, port: int = DEFAULT_PORT,
                          timeout: int = DEFAULT_TIMEOUT) -> CertificateInfo:
    """Connect via TLS and return certificate + negotiated protocol details.

    Raises ssl.SSLError / OSError / socket.timeout on connection failure -
    callers are expected to catch these (see check_tls).
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version() or "unknown"

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days

    subject = ", ".join(f"{k}={v}" for tup in cert.get("subject", []) for k, v in tup)
    issuer = ", ".join(f"{k}={v}" for tup in cert.get("issuer", []) for k, v in tup)

    return CertificateInfo(
        subject=subject or "unknown",
        issuer=issuer or "unknown",
        not_after=not_after,
        protocol=protocol,
        days_until_expiry=days_left,
    )


def evaluate_certificate(info: CertificateInfo) -> list[Finding]:
    """Turn a CertificateInfo into findings (pure function, easy to unit test)."""
    findings: list[Finding] = []

    if info.days_until_expiry < 0:
        findings.append(Finding(
            id="TLS-CERT-EXPIRED",
            title="TLS certificate has expired",
            severity=Severity.CRITICAL,
            category="tls",
            description=f"The certificate for this host expired {-info.days_until_expiry} day(s) ago.",
            recommendation="Renew the certificate immediately.",
            evidence=f"notAfter={info.not_after.isoformat()}",
        ))
    elif info.days_until_expiry <= EXPIRY_WARNING_DAYS:
        findings.append(Finding(
            id="TLS-CERT-EXPIRING-SOON",
            title="TLS certificate expires soon",
            severity=Severity.MEDIUM,
            category="tls",
            description=f"The certificate expires in {info.days_until_expiry} day(s).",
            recommendation="Renew the certificate before it expires to avoid an outage.",
            evidence=f"notAfter={info.not_after.isoformat()}",
        ))

    if info.protocol in _WEAK_PROTOCOLS:
        findings.append(Finding(
            id="TLS-WEAK-PROTOCOL",
            title=f"Weak TLS protocol negotiated ({info.protocol})",
            severity=Severity.HIGH,
            category="tls",
            description=f"The server negotiated {info.protocol}, which has known "
                        f"cryptographic weaknesses and is deprecated.",
            recommendation="Disable protocols below TLS 1.2 on the server.",
            evidence=f"protocol={info.protocol}",
        ))

    return findings


def check_tls(hostname: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    """Connect to hostname:port and return TLS findings. Errors become an INFO finding."""
    try:
        info = get_certificate_info(hostname, port=port, timeout=timeout)
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return [Finding(
            id="TLS-CONNECT-FAILED",
            title="Could not establish a TLS connection",
            severity=Severity.INFO,
            category="tls",
            description=f"TLS handshake to {hostname}:{port} failed: {exc}",
            recommendation="Verify the host serves HTTPS on this port and retry.",
        )]
    return evaluate_certificate(info)
