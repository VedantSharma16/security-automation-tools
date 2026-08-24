"""TLS certificate and protocol checks.

The real network call (:func:`webauditor.fetch.get_tls_info`) is injected as
``tls_info_fn`` so tests can supply canned cert/protocol/cipher dicts without
opening a socket.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from .fetch import get_tls_info
from .findings import Finding, Severity

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")
EXPIRY_WARNING_DAYS = 30

_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def check_tls(
    hostname: str,
    port: int = 443,
    tls_info_fn: Callable[[str, int], dict] = get_tls_info,
) -> list[Finding]:
    try:
        info = tls_info_fn(hostname, port)
    except Exception as exc:  # noqa: BLE001 - any transport/handshake failure
        return [
            Finding(
                id="tls-connection-failed",
                title="Could not establish a TLS connection",
                severity=Severity.INFO,
                owasp_category="A02:2021 Cryptographic Failures",
                description="A TLS handshake to this host/port could not be "
                "completed, so no certificate or protocol analysis could be "
                "performed.",
                evidence=str(exc),
                remediation="Verify the host is reachable on the given port and "
                "presents a valid TLS certificate.",
            )
        ]

    findings: list[Finding] = []
    protocol = info.get("protocol")
    cipher = info.get("cipher") or (None, None, None)
    cipher_name = cipher[0] if cipher else None
    cert = info.get("cert") or {}

    if protocol in WEAK_PROTOCOLS:
        findings.append(
            Finding(
                id="tls-outdated-protocol",
                title=f"Outdated TLS protocol negotiated: {protocol}",
                severity=Severity.HIGH,
                owasp_category="A02:2021 Cryptographic Failures",
                description=f"The server negotiated {protocol}, which has known "
                "weaknesses and is deprecated by all major browsers.",
                evidence=f"protocol={protocol}",
                remediation="Disable protocols older than TLS 1.2 and prefer "
                "TLS 1.3 where supported.",
            )
        )

    if cipher_name and any(marker in cipher_name for marker in WEAK_CIPHER_MARKERS):
        findings.append(
            Finding(
                id="tls-weak-cipher",
                title=f"Weak cipher suite negotiated: {cipher_name}",
                severity=Severity.CRITICAL,
                owasp_category="A02:2021 Cryptographic Failures",
                description="The negotiated cipher suite uses an algorithm with "
                "known cryptographic weaknesses.",
                evidence=f"cipher={cipher_name}",
                remediation="Restrict the server's cipher suite list to modern "
                "AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
            )
        )

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, _CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    Finding(
                        id="tls-cert-expired",
                        title="TLS certificate has expired",
                        severity=Severity.CRITICAL,
                        owasp_category="A02:2021 Cryptographic Failures",
                        description="The presented certificate's notAfter date is in "
                        "the past. Browsers will hard-block visitors.",
                        evidence=f"notAfter={not_after}",
                        remediation="Renew the certificate immediately.",
                    )
                )
            elif days_left <= EXPIRY_WARNING_DAYS:
                findings.append(
                    Finding(
                        id="tls-cert-expiring-soon",
                        title=f"TLS certificate expires in {days_left} day(s)",
                        severity=Severity.MEDIUM,
                        owasp_category="A02:2021 Cryptographic Failures",
                        description="The certificate is within the renewal warning "
                        "window.",
                        evidence=f"notAfter={not_after}",
                        remediation="Renew the certificate before expiry; consider "
                        "automated renewal (e.g. ACME/Let's Encrypt).",
                    )
                )
        except ValueError:
            pass

    return findings
