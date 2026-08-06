"""TLS/SSL certificate reconnaissance: expiry, issuer, SANs, and negotiated
protocol version.

The handshake is isolated behind `connect_fn` so certificate-expiry and
weak-protocol logic can be unit-tested with a synthetic certificate dict
instead of a real TLS connection.
"""
from __future__ import annotations

import datetime
import socket
import ssl
from typing import Callable, Dict, List, Optional

from ..models import Finding, ToolResult

CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"

ConnectFn = Callable[[str, int], Dict]

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _default_connect(hostname: str, port: int = 443) -> Dict:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()
    return {"cert": cert, "protocol": protocol}


def run(hostname: str, port: int = 443, connect_fn: ConnectFn = _default_connect) -> ToolResult:
    try:
        raw = connect_fn(hostname, port)
    except Exception as exc:
        return ToolResult(
            tool="tls",
            data={"error": str(exc)},
            findings=[
                Finding(
                    tool="tls",
                    severity="high",
                    title="TLS handshake failed",
                    detail=f"Could not establish a validated TLS connection to {hostname}:{port}: {exc}",
                    recommendation="Verify the certificate chain is valid, complete, and not expired.",
                )
            ],
        )

    info = _parse_cert(raw)
    findings = analyze_cert(info)
    return ToolResult(tool="tls", data=info, findings=findings)


def _parse_cert(raw: Dict) -> Dict:
    cert = raw.get("cert") or {}
    not_after_str = cert.get("notAfter")
    not_before_str = cert.get("notBefore")
    not_after = _parse_date(not_after_str)

    days_remaining: Optional[int] = None
    if not_after:
        days_remaining = (not_after - datetime.datetime.now(datetime.timezone.utc)).days

    subject = _flatten(cert.get("subject", ()))
    issuer = _flatten(cert.get("issuer", ()))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before_str,
        "not_after": not_after_str,
        "days_remaining": days_remaining,
        "san": sans,
        "protocol": raw.get("protocol"),
    }


def _flatten(name_tuple) -> Dict[str, str]:
    flat: Dict[str, str] = {}
    for rdn in name_tuple:
        for key, value in rdn:
            flat[key] = value
    return flat


def _parse_date(value: Optional[str]) -> Optional[datetime.datetime]:
    if not value:
        return None
    try:
        parsed = datetime.datetime.strptime(value, CERT_DATE_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=datetime.timezone.utc)


def analyze_cert(info: Dict) -> List[Finding]:
    findings: List[Finding] = []
    days_remaining = info.get("days_remaining")

    if days_remaining is not None:
        if days_remaining < 0:
            findings.append(
                Finding(
                    tool="tls",
                    severity="critical",
                    title="TLS certificate is expired",
                    detail=f"Certificate expired {abs(days_remaining)} day(s) ago.",
                    recommendation="Renew the TLS certificate immediately.",
                )
            )
        elif days_remaining < 14:
            findings.append(
                Finding(
                    tool="tls",
                    severity="high",
                    title="TLS certificate expiring very soon",
                    detail=f"Certificate expires in {days_remaining} day(s).",
                    recommendation="Renew the certificate now to avoid a service outage.",
                )
            )
        elif days_remaining < 30:
            findings.append(
                Finding(
                    tool="tls",
                    severity="medium",
                    title="TLS certificate expiring soon",
                    detail=f"Certificate expires in {days_remaining} day(s).",
                    recommendation="Schedule certificate renewal.",
                )
            )

    protocol = info.get("protocol")
    if protocol in WEAK_PROTOCOLS:
        findings.append(
            Finding(
                tool="tls",
                severity="high",
                title="Weak TLS protocol negotiated",
                detail=f"Connection negotiated {protocol}.",
                recommendation="Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or higher.",
            )
        )

    return findings
