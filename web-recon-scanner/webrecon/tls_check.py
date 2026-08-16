"""TLS/SSL certificate and negotiated-protocol inspection.

`inspect_certificate` is pure (takes the dict shape `ssl.getpeercert()`
returns plus a protocol string) so it's fully unit testable without a
socket. `fetch_certificate` does the actual handshake and is exercised
only via the CLI / integration path.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"
EXPIRY_WARNING_DAYS = 30
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass(frozen=True)
class TLSFinding:
    severity: str
    message: str


@dataclass(frozen=True)
class TLSReport:
    subject_cn: str | None
    issuer_cn: str | None
    not_before: datetime | None
    not_after: datetime | None
    protocol_version: str | None
    days_until_expiry: int | None
    findings: tuple


def parse_cert_date(value: str) -> datetime:
    return datetime.strptime(value, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)


def _dn_component(rdn_sequence, key: str) -> str | None:
    for rdn in rdn_sequence or ():
        for attr_key, attr_value in rdn:
            if attr_key == key:
                return attr_value
    return None


def inspect_certificate(cert: dict, protocol_version: str | None, now: datetime | None = None) -> TLSReport:
    now = now or datetime.now(timezone.utc)
    findings = []

    not_before = parse_cert_date(cert["notBefore"]) if cert.get("notBefore") else None
    not_after = parse_cert_date(cert["notAfter"]) if cert.get("notAfter") else None
    subject_cn = _dn_component(cert.get("subject"), "commonName")
    issuer_cn = _dn_component(cert.get("issuer"), "commonName")

    days_until_expiry = None
    if not_after is not None:
        days_until_expiry = (not_after - now).days
        if days_until_expiry < 0:
            findings.append(TLSFinding("critical", f"Certificate expired {-days_until_expiry} day(s) ago."))
        elif days_until_expiry < EXPIRY_WARNING_DAYS:
            findings.append(TLSFinding("high", f"Certificate expires in {days_until_expiry} day(s)."))

    if not_before is not None and not_before > now:
        findings.append(TLSFinding("high", "Certificate is not yet valid (notBefore is in the future)."))

    if subject_cn and issuer_cn and subject_cn == issuer_cn:
        findings.append(
            TLSFinding("medium", f"Certificate for {subject_cn!r} appears self-signed (subject == issuer).")
        )

    if protocol_version in WEAK_PROTOCOLS:
        findings.append(TLSFinding("critical", f"Weak/deprecated protocol negotiated: {protocol_version}."))

    if not findings:
        findings.append(TLSFinding("info", "No TLS certificate or protocol issues detected."))

    return TLSReport(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        not_before=not_before,
        not_after=not_after,
        protocol_version=protocol_version,
        days_until_expiry=days_until_expiry,
        findings=tuple(findings),
    )


def fetch_certificate(host: str, port: int = 443, timeout: float = 5.0):
    """Perform a live TLS handshake and return `(cert_dict, protocol_version)`.

    Uses `ssl.create_default_context()` (verifies the chain against the
    system trust store) purely to retrieve certificate metadata for
    reporting — a scan target with an invalid chain will raise here rather
    than silently succeed, which is surfaced to the caller as an error.
    """
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol_version = tls_sock.version()
    return cert, protocol_version
