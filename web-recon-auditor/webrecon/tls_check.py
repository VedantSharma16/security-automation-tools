"""Lightweight TLS posture check: protocol version and certificate expiry.

Deliberately uses only the standard library (``ssl`` + ``socket``) rather
than shelling out to ``openssl`` or adding a dependency — this check is a
handshake away from any https target, so it stays simple and portable.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .findings import Finding

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_EXPIRY_WARNING_WINDOW = timedelta(days=30)
_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


@dataclass
class TlsInfo:
    checked: bool
    protocol: str | None = None
    not_after: datetime | None = None
    error: str | None = None


def inspect_tls(host: str, port: int = 443, timeout: float = 6.0) -> TlsInfo:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                protocol = tls_sock.version()
                cert = tls_sock.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        return TlsInfo(checked=False, error=str(exc))

    not_after = None
    raw_not_after = cert.get("notAfter") if cert else None
    if raw_not_after:
        try:
            not_after = datetime.strptime(raw_not_after, _CERT_DATE_FORMAT).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            not_after = None

    return TlsInfo(checked=True, protocol=protocol, not_after=not_after)


def analyze_tls(info: TlsInfo, now: datetime | None = None) -> list[Finding]:
    if not info.checked:
        return [
            Finding(
                id="tls-check-failed",
                category="tls",
                severity="info",
                title="Could not complete a TLS handshake",
                detail=f"TLS inspection failed: {info.error}",
                recommendation="Verify the host accepts TLS connections on the "
                "probed port and that no firewall is blocking the handshake.",
            )
        ]

    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    if info.protocol in _WEAK_PROTOCOLS:
        findings.append(
            Finding(
                id="tls-weak-protocol",
                category="tls",
                severity="high",
                title=f"Weak TLS protocol negotiated: {info.protocol}",
                detail=f"The server negotiated {info.protocol}, which has known "
                "cryptographic weaknesses and is deprecated by every major "
                "browser and RFC 8996.",
                recommendation="Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 at the web "
                "server or load balancer; require TLSv1.2 or newer.",
                evidence={"protocol": info.protocol},
            )
        )

    if info.not_after is not None:
        if info.not_after < now:
            findings.append(
                Finding(
                    id="tls-cert-expired",
                    category="tls",
                    severity="critical",
                    title="TLS certificate has expired",
                    detail=f"Certificate expired on {info.not_after.isoformat()}.",
                    recommendation="Renew the certificate immediately; most "
                    "browsers will hard-block visitors until it's replaced.",
                    evidence={"not_after": info.not_after.isoformat()},
                )
            )
        elif info.not_after - now <= _EXPIRY_WARNING_WINDOW:
            findings.append(
                Finding(
                    id="tls-cert-expiring-soon",
                    category="tls",
                    severity="medium",
                    title="TLS certificate expires within 30 days",
                    detail=f"Certificate expires on {info.not_after.isoformat()}.",
                    recommendation="Renew the certificate now, or confirm "
                    "automated renewal (e.g. ACME/Let's Encrypt) is working.",
                    evidence={"not_after": info.not_after.isoformat()},
                )
            )

    return findings
