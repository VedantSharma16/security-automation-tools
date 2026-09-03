"""HTTP header / page-title / TLS-certificate fingerprinting.

Stdlib only. ``fetch_http`` and ``fetch_tls_cert`` are injectable so unit
tests can exercise :func:`fingerprint_http`'s parsing and finding-relevant
logic without opening real sockets.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from typing import Callable

NOT_AFTER_FORMAT = "%b %d %H:%M:%S %Y %Z"
WEB_PORTS = (80, 443, 8000, 8080, 8443)


@dataclass
class HttpFingerprint:
    port: int
    scheme: str
    status: int | None = None
    server: str | None = None
    title: str | None = None
    headers: dict = field(default_factory=dict)
    tls_not_after: str | None = None
    tls_days_remaining: int | None = None
    error: str | None = None
    tls_error: str | None = None


HttpFetcher = Callable[[str, int, float, str], tuple[int, dict, str]]
TlsFetcher = Callable[[str, int, float], dict]


def extract_title(body: str) -> str | None:
    lower = body.lower()
    start = lower.find("<title>")
    if start == -1:
        return None
    end = lower.find("</title>", start)
    if end == -1:
        return None
    title = body[start + len("<title>") : end].strip()
    return title[:200] or None


def parse_not_after(not_after: str) -> datetime | None:
    try:
        return datetime.strptime(not_after, NOT_AFTER_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fetch_http(host: str, port: int, timeout: float, scheme: str) -> tuple[int, dict, str]:
    if scheme == "https":
        conn = HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
    else:
        conn = HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", "/", headers={"User-Agent": "recon-agent/0.1"})
        response = conn.getresponse()
        headers = dict(response.getheaders())
        body = response.read(65536).decode("utf-8", errors="ignore")
        return response.status, headers, body
    finally:
        conn.close()


def fetch_tls_cert(host: str, port: int, timeout: float) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            return tls_sock.getpeercert()


def fingerprint_http(
    host: str,
    port: int,
    timeout: float = 3.0,
    *,
    http_fetcher: HttpFetcher = fetch_http,
    tls_fetcher: TlsFetcher = fetch_tls_cert,
) -> HttpFingerprint:
    """Fetch headers/title (and, over HTTPS, certificate expiry) for one port.

    Never raises: connection and TLS failures are recorded on the returned
    fingerprint (``error`` / ``tls_error``) so a single unreachable port
    doesn't abort a multi-port fingerprinting pass.
    """
    scheme = "https" if port in (443, 8443) else "http"
    fingerprint = HttpFingerprint(port=port, scheme=scheme)

    try:
        status, headers, body = http_fetcher(host, port, timeout, scheme)
        fingerprint.status = status
        fingerprint.headers = headers
        fingerprint.server = headers.get("Server")
        fingerprint.title = extract_title(body)
    except Exception as exc:  # noqa: BLE001 - unreachable/refused/reset ports are expected
        fingerprint.error = str(exc)
        return fingerprint

    if scheme == "https":
        try:
            cert = tls_fetcher(host, port, timeout) or {}
            not_after = cert.get("notAfter")
            fingerprint.tls_not_after = not_after
            expiry = parse_not_after(not_after) if not_after else None
            if expiry:
                fingerprint.tls_days_remaining = (expiry - datetime.now(timezone.utc)).days
        except Exception as exc:  # noqa: BLE001 - self-signed/expired/handshake failures
            fingerprint.tls_error = str(exc)

    return fingerprint
