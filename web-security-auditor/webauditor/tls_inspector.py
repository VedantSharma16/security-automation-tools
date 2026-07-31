"""TLS/certificate posture inspection.

Opens a real TLS handshake to the target host so we can report the negotiated
protocol version, cipher, and certificate expiry -- the kind of quick posture
check normally done with ``openssl s_client`` during a recon or hardening pass.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass
from typing import List, Optional

from .models import Finding, Severity, Status

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_CRITICAL_DAYS = 0
EXPIRY_HIGH_DAYS = 14
EXPIRY_MEDIUM_DAYS = 30


@dataclass
class TLSInfo:
    host: str
    port: int
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _name_to_str(name_tuples) -> str:
    parts = []
    for rdn in name_tuples or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _parse_cert_time(value: str) -> datetime.datetime:
    normalized = " ".join(value.split())
    parsed = datetime.datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=datetime.timezone.utc)


def inspect(host: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    """Connect to ``host:port`` and report the negotiated TLS session details."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                not_after_raw = cert.get("notAfter") if cert else None
                days_until_expiry = None
                if not_after_raw:
                    expiry = _parse_cert_time(not_after_raw)
                    days_until_expiry = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                return TLSInfo(
                    host=host,
                    port=port,
                    protocol=tls_sock.version(),
                    cipher=cipher[0] if cipher else None,
                    not_after=not_after_raw,
                    days_until_expiry=days_until_expiry,
                    issuer=_name_to_str(cert.get("issuer")) if cert else None,
                    subject=_name_to_str(cert.get("subject")) if cert else None,
                )
    except (ssl.SSLError, socket.timeout, socket.gaierror, OSError, ValueError) as exc:
        return TLSInfo(host=host, port=port, error=str(exc))


def evaluate_tls(tls_info: TLSInfo) -> List[Finding]:
    """Turn a ``TLSInfo`` snapshot into pass/warn/fail findings."""
    if not tls_info.ok:
        return [
            Finding(
                "tls-handshake", "TLS Handshake", Status.FAIL, Severity.HIGH,
                f"Could not establish a TLS connection to {tls_info.host}:{tls_info.port}: {tls_info.error}",
                "Verify the certificate chain, hostname, and that the service listens on the expected TLS port.",
            )
        ]

    findings = []

    if tls_info.protocol in WEAK_PROTOCOLS:
        findings.append(Finding(
            "tls-protocol", "TLS Protocol Version", Status.FAIL, Severity.CRITICAL,
            f"Negotiated {tls_info.protocol}, which is deprecated and considered insecure.",
            "Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 and require TLS 1.2 or newer.",
        ))
    else:
        findings.append(Finding(
            "tls-protocol", "TLS Protocol Version", Status.PASS, Severity.INFO,
            f"Negotiated {tls_info.protocol}.", None,
        ))

    if tls_info.days_until_expiry is None:
        findings.append(Finding(
            "tls-expiry", "Certificate Expiry", Status.WARN, Severity.LOW,
            "Certificate expiry date could not be determined.", None,
        ))
    elif tls_info.days_until_expiry < EXPIRY_CRITICAL_DAYS:
        findings.append(Finding(
            "tls-expiry", "Certificate Expiry", Status.FAIL, Severity.CRITICAL,
            f"Certificate expired {abs(tls_info.days_until_expiry)} day(s) ago ({tls_info.not_after}).",
            "Renew and deploy a new certificate immediately.",
        ))
    elif tls_info.days_until_expiry < EXPIRY_HIGH_DAYS:
        findings.append(Finding(
            "tls-expiry", "Certificate Expiry", Status.FAIL, Severity.HIGH,
            f"Certificate expires in {tls_info.days_until_expiry} day(s) ({tls_info.not_after}).",
            "Renew the certificate now to avoid an outage.",
        ))
    elif tls_info.days_until_expiry < EXPIRY_MEDIUM_DAYS:
        findings.append(Finding(
            "tls-expiry", "Certificate Expiry", Status.WARN, Severity.MEDIUM,
            f"Certificate expires in {tls_info.days_until_expiry} day(s) ({tls_info.not_after}).",
            "Schedule certificate renewal.",
        ))
    else:
        findings.append(Finding(
            "tls-expiry", "Certificate Expiry", Status.PASS, Severity.INFO,
            f"Certificate valid for {tls_info.days_until_expiry} more day(s).", None,
        ))

    return findings
