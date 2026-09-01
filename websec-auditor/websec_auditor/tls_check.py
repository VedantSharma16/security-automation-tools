"""TLS/certificate posture check.

Establishes a normal TLS handshake (the same one any browser performs) and
inspects the negotiated protocol version and the leaf certificate's
validity window. No exploitation, no cipher downgrade attempts.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .findings import Finding

DEFAULT_TIMEOUT = 6.0
_CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"

# Connector signature: (hostname, port, timeout) -> TLSInfo
TLSConnector = Callable[[str, int, float], "TLSInfo"]


@dataclass
class TLSInfo:
    protocol: str | None
    cipher: str | None
    not_after: datetime | None
    not_before: datetime | None
    issuer: str | None
    subject: str | None
    san: list[str]
    error: str | None = None


def _default_connector(hostname: str, port: int, timeout: float) -> TLSInfo:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                return TLSInfo(
                    protocol=tls_sock.version(),
                    cipher=cipher[0] if cipher else None,
                    not_after=_parse_cert_date(cert.get("notAfter")),
                    not_before=_parse_cert_date(cert.get("notBefore")),
                    issuer=_format_name(cert.get("issuer")),
                    subject=_format_name(cert.get("subject")),
                    san=[value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"],
                )
    except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return TLSInfo(
            protocol=None,
            cipher=None,
            not_after=None,
            not_before=None,
            issuer=None,
            subject=None,
            san=[],
            error=str(exc),
        )


def _parse_cert_date(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.strptime(value, _CERT_DATE_FMT).replace(tzinfo=timezone.utc)


def _format_name(name_tuples) -> str | None:
    if not name_tuples:
        return None
    flat = [item for group in name_tuples for item in group]
    return ", ".join(f"{k}={v}" for k, v in flat)


def fetch_tls_info(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    connector: TLSConnector | None = None,
) -> TLSInfo:
    connect = connector or _default_connector
    return connect(hostname, port, timeout)


_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_EXPIRY_WARNING_DAYS = 30


def analyze_tls(info: TLSInfo, *, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    if info.error:
        findings.append(
            Finding(
                id="tls-handshake-failed",
                severity="high",
                category="tls",
                message=f"TLS handshake failed: {info.error}",
                recommendation="Verify the certificate chain and that a modern TLS stack is configured.",
            )
        )
        return findings

    if info.protocol in _WEAK_PROTOCOLS:
        findings.append(
            Finding(
                id="weak-tls-protocol",
                severity="critical",
                category="tls",
                message=f"Server negotiated {info.protocol}, which is deprecated and considered insecure.",
                recommendation="Disable TLS 1.1 and below; require TLS 1.2 or, ideally, TLS 1.3 only.",
                evidence={"protocol": info.protocol},
            )
        )

    if info.not_after:
        days_left = (info.not_after - now).days
        if days_left < 0:
            findings.append(
                Finding(
                    id="cert-expired",
                    severity="critical",
                    category="tls",
                    message=f"Certificate expired {-days_left} day(s) ago ({info.not_after.date()}).",
                    recommendation="Renew the certificate immediately.",
                )
            )
        elif days_left <= _EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    id="cert-expiring-soon",
                    severity="medium",
                    category="tls",
                    message=f"Certificate expires in {days_left} day(s) ({info.not_after.date()}).",
                    recommendation="Renew the certificate before it expires; consider automated renewal (ACME/Let's Encrypt).",
                )
            )

    return findings
