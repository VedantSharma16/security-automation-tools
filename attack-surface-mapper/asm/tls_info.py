"""TLS certificate and protocol inspection.

Opens a TLS connection to the target and inspects the negotiated protocol
version and the presented certificate's validity window. Expired or
soon-to-expire certificates and deprecated protocol versions (TLS 1.0/1.1,
both formally deprecated by RFC 8996) are common, high-value findings in a
real external assessment because they're both easy to miss operationally
and directly exploitable or disruptive.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Callable

from .findings import Finding, Severity

_DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
EXPIRY_CRITICAL_DAYS = 0
EXPIRY_HIGH_DAYS = 14
EXPIRY_MEDIUM_DAYS = 30

# (cert dict from ssl.SSLSocket.getpeercert(), negotiated protocol version)
ConnectFn = Callable[[str, int, float], tuple[dict, str]]


def _default_connect(domain: str, port: int, timeout: float) -> tuple[dict, str]:
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
            return tls_sock.getpeercert(), tls_sock.version()


def _parse_name(name_tuples) -> dict:
    return {key: value for rdn in name_tuples for key, value in rdn}


def get_certificate_info(
    domain: str, port: int = 443, timeout: float = 5.0, connect_fn: ConnectFn | None = None
) -> dict | None:
    """Return certificate/protocol info for `domain`, or None if TLS failed entirely."""
    connect_fn = connect_fn or _default_connect
    try:
        cert, protocol = connect_fn(domain, port, timeout)
    except (socket.error, ssl.SSLError, socket.timeout):
        return None

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    days_until_expiry = (not_after - datetime.now(timezone.utc)).days

    return {
        "subject": _parse_name(cert.get("subject", ())),
        "issuer": _parse_name(cert.get("issuer", ())),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "protocol": protocol,
    }


def build_findings(domain: str, info: dict | None) -> list[Finding]:
    if info is None:
        return [
            Finding(
                source="tls",
                severity=Severity.MEDIUM,
                title="TLS connection failed",
                detail=f"Could not establish a TLS connection to {domain}:443.",
            )
        ]

    findings = [
        Finding(
            source="tls",
            severity=Severity.INFO,
            title="Certificate presented",
            detail=(
                f"Issued by {info['issuer'].get('organizationName', 'unknown issuer')}, "
                f"expires {info['not_after']}, negotiated {info['protocol']}."
            ),
        )
    ]

    days = info["days_until_expiry"]
    if days < EXPIRY_CRITICAL_DAYS:
        findings.append(
            Finding(
                source="tls",
                severity=Severity.CRITICAL,
                title="TLS certificate expired",
                detail=f"The certificate for {domain} expired on {info['not_after']}.",
            )
        )
    elif days < EXPIRY_HIGH_DAYS:
        findings.append(
            Finding(
                source="tls",
                severity=Severity.HIGH,
                title="TLS certificate expiring imminently",
                detail=f"The certificate for {domain} expires in {days} day(s) ({info['not_after']}).",
            )
        )
    elif days < EXPIRY_MEDIUM_DAYS:
        findings.append(
            Finding(
                source="tls",
                severity=Severity.MEDIUM,
                title="TLS certificate expiring soon",
                detail=f"The certificate for {domain} expires in {days} day(s) ({info['not_after']}).",
            )
        )

    if info["protocol"] in _DEPRECATED_PROTOCOLS:
        findings.append(
            Finding(
                source="tls",
                severity=Severity.HIGH,
                title="Deprecated TLS protocol negotiated",
                detail=(
                    f"{domain} negotiated {info['protocol']}, which is deprecated "
                    "(RFC 8996) and should be disabled in favor of TLS 1.2+."
                ),
            )
        )

    return findings
