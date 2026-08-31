"""Passive TLS certificate inspection.

The socket/SSL connection is made through an injectable ``connect`` callable
so tests can supply a fake "connection" object (anything exposing
``getpeercert(binary_form=True)``, ``version()``, and ``cipher()``) instead
of opening a real TLS session.

Certificate fields are parsed from the raw DER bytes with ``cryptography``
rather than via ``ssl.SSLSocket.getpeercert()``'s dict form: that dict is
only populated when the peer cert passes chain validation, so it comes back
empty for the self-signed/expired/unusual certs a recon tool most needs to
inspect. We deliberately connect with ``CERT_NONE`` (recon shouldn't refuse
to look at a cert just because it doesn't validate) and parse the bytes
ourselves instead.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARNING_DAYS = 30


@dataclass
class TlsFinding:
    host: str
    port: int
    connected: bool = False
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    error: str | None = None


def _default_connect(host: str, port: int, timeout: float):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    return context.wrap_socket(raw_sock, server_hostname=host)


def _cert_time(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def check_tls(
    host: str,
    port: int = 443,
    connect=None,
    timeout: float = 5.0,
) -> TlsFinding:
    """Connect to ``host``:``port`` and inspect the presented certificate."""
    connector = connect or _default_connect
    finding = TlsFinding(host=host, port=port)

    try:
        conn = connector(host, port, timeout)
    except (OSError, ssl.SSLError) as exc:
        finding.error = str(exc)
        return finding

    try:
        der_cert = conn.getpeercert(binary_form=True)
        finding.connected = True
        finding.protocol = conn.version()
        cipher = conn.cipher()
        finding.cipher = cipher[0] if cipher else None

        if der_cert:
            cert = x509.load_der_x509_certificate(der_cert)
            finding.subject = cert.subject.rfc4514_string()
            finding.issuer = cert.issuer.rfc4514_string()

            not_before = _cert_time(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)
            not_after = _cert_time(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
            finding.not_before = not_before.isoformat()
            finding.not_after = not_after.isoformat()

            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                finding.subject_alt_names = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                finding.subject_alt_names = []

            delta = not_after - datetime.now(timezone.utc)
            finding.days_until_expiry = delta.days
            if delta.days < 0:
                finding.issues.append(f"Certificate expired {-delta.days} day(s) ago")
            elif delta.days <= EXPIRY_WARNING_DAYS:
                finding.issues.append(f"Certificate expires in {delta.days} day(s)")
        else:
            finding.issues.append("No certificate returned by peer")

        if finding.protocol in WEAK_PROTOCOLS:
            finding.issues.append(f"Weak/deprecated protocol negotiated: {finding.protocol}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return finding
