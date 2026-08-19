"""Inspect the TLS certificate presented by a host, independent of HTTP fetching.

Like `http_probe`, the actual socket/TLS handshake is behind an injectable
`CertFetcher` so certificate-logic (expiry math, obsolete-protocol flags) can
be unit tested without a network connection.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlparse

CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"
OBSOLETE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TlsInfo:
    host: str
    protocol_version: str | None
    subject: str | None
    issuer: str | None
    not_after: str | None
    days_until_expiry: int | None
    error: str | None = None


CertFetcher = Callable[[str, int, float], dict]


def default_cert_fetcher(host: str, port: int, timeout: float) -> dict:
    """Real fetcher: open a TLS connection and return the peer certificate dict."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = dict(tls_sock.getpeercert())
            cert["_protocol_version"] = tls_sock.version()
            return cert


def _name_from_rdn_sequence(seq) -> str | None:
    if not seq:
        return None
    return ", ".join(f"{k}={v}" for rdn in seq for k, v in rdn)


def _days_until_expiry(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        expiry = datetime.strptime(not_after, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (expiry - datetime.now(timezone.utc)).days


def inspect(url: str, timeout: float = 5.0, cert_fetcher: CertFetcher = default_cert_fetcher) -> TlsInfo:
    """Inspect the certificate for `url`. Non-https URLs return a populated `error`."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not host:
        return TlsInfo(host, None, None, None, None, None, error="not an https URL")

    port = parsed.port or 443
    try:
        cert = cert_fetcher(host, port, timeout)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return TlsInfo(host, None, None, None, None, None, error=str(exc))

    not_after = cert.get("notAfter")
    return TlsInfo(
        host=host,
        protocol_version=cert.get("_protocol_version"),
        subject=_name_from_rdn_sequence(cert.get("subject")),
        issuer=_name_from_rdn_sequence(cert.get("issuer")),
        not_after=not_after,
        days_until_expiry=_days_until_expiry(not_after),
    )


def from_fixture(host: str, data: dict) -> TlsInfo:
    """Build TlsInfo from an already-flat fixture dict (offline `analyze` mode)."""
    not_after = data.get("not_after")
    return TlsInfo(
        host=host,
        protocol_version=data.get("protocol_version"),
        subject=data.get("subject"),
        issuer=data.get("issuer"),
        not_after=not_after,
        days_until_expiry=_days_until_expiry(not_after),
        error=data.get("error"),
    )
