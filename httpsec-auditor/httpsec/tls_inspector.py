"""TLS handshake/certificate inspection.

`inspect()` is the network boundary (opens a real TLS connection). `analyze()`
is a pure function over a `TLSInfo` so it can be unit tested with synthetic
certificate data instead of a live socket.
"""

from __future__ import annotations

import datetime
import socket
import ssl

from .models import Finding, TLSInfo

# TLS 1.0/1.1 are deprecated per RFC 8996; SSLv3 and below are broken.
DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_SUBSTRINGS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")
EXPIRY_WARNING_DAYS = 30


def _cert_common_name(cert: dict, field: str) -> str:
    for rdn in cert.get(field, ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return ""


def _parse_cert_time(value: str) -> datetime.datetime:
    # OpenSSL/ssl module format, e.g. "Jun  1 12:00:00 2027 GMT"
    return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def inspect(hostname: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    """Open a TLS connection and return normalized certificate/handshake info."""
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            cipher_name, protocol, cipher_bits = tls_sock.cipher()
            not_after = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")
            days_left = -1
            if not_after:
                expiry = _parse_cert_time(not_after)
                days_left = (expiry - datetime.datetime.utcnow()).days
            san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
            return TLSInfo(
                protocol=protocol,
                cipher_name=cipher_name,
                cipher_bits=cipher_bits,
                not_before=not_before,
                not_after=not_after,
                days_until_expiry=days_left,
                subject_cn=_cert_common_name(cert, "subject"),
                issuer_cn=_cert_common_name(cert, "issuer"),
                san=san,
            )


def analyze(tls_info: TLSInfo, hostname: str = "") -> list[Finding]:
    """Evaluate a TLSInfo snapshot and return findings. Pure/offline-testable."""
    findings: list[Finding] = []

    if tls_info.protocol in DEPRECATED_PROTOCOLS:
        findings.append(
            Finding(
                id="tls-deprecated-protocol",
                category="tls",
                severity="high",
                title=f"Deprecated TLS protocol negotiated: {tls_info.protocol}",
                description=(
                    f"The server negotiated {tls_info.protocol}, which is "
                    "deprecated (RFC 8996) and vulnerable to known "
                    "downgrade/plaintext-recovery attacks (e.g. POODLE, BEAST)."
                ),
                remediation="Disable TLS 1.0/1.1 and SSLv3 server-side; require TLS 1.2 or higher.",
                evidence=f"negotiated protocol={tls_info.protocol}",
            )
        )

    if any(weak in tls_info.cipher_name.upper() for weak in WEAK_CIPHER_SUBSTRINGS):
        findings.append(
            Finding(
                id="tls-weak-cipher",
                category="tls",
                severity="high",
                title=f"Weak cipher suite negotiated: {tls_info.cipher_name}",
                description=(
                    "The negotiated cipher suite uses a broken or weak "
                    "algorithm (RC4/DES/3DES/NULL/EXPORT/MD5)."
                ),
                remediation="Restrict the server's cipher list to modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
                evidence=f"cipher={tls_info.cipher_name}",
            )
        )

    if tls_info.days_until_expiry < 0:
        findings.append(
            Finding(
                id="tls-cert-expired",
                category="tls",
                severity="critical",
                title="TLS certificate has expired",
                description="The server's TLS certificate's notAfter date is in the past.",
                remediation="Renew the certificate immediately.",
                evidence=f"notAfter={tls_info.not_after}",
            )
        )
    elif tls_info.days_until_expiry <= EXPIRY_WARNING_DAYS:
        findings.append(
            Finding(
                id="tls-cert-expiring-soon",
                category="tls",
                severity="medium",
                title=f"TLS certificate expires in {tls_info.days_until_expiry} day(s)",
                description="The certificate is approaching its expiry date.",
                remediation="Renew the certificate before it expires to avoid a browser trust failure.",
                evidence=f"notAfter={tls_info.not_after}",
            )
        )

    if hostname and tls_info.subject_cn != hostname and hostname not in tls_info.san:
        findings.append(
            Finding(
                id="tls-hostname-mismatch",
                category="tls",
                severity="high",
                title="Certificate does not cover the requested hostname",
                description=(
                    f"Requested host {hostname!r} is neither the certificate's "
                    f"CN ({tls_info.subject_cn!r}) nor in its SAN list."
                ),
                remediation="Issue a certificate whose SAN list includes every hostname the server answers for.",
                evidence=f"cn={tls_info.subject_cn}, san={tls_info.san}",
            )
        )

    return findings
