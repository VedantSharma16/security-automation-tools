"""Network layer: fetches a single URL and normalizes the response.

Kept deliberately thin and injectable — every check module operates on the
plain :class:`HttpResponse` / :class:`TLSInfo` dataclasses below, never on
sockets directly, so the whole audit pipeline is testable without any real
network access (see ``tests/`` for fake-transport examples).
"""

from __future__ import annotations

import datetime as _dt
import http.client
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 10.0
DEFAULT_UA = "http-security-auditor/0.1 (+authorized-security-testing)"


@dataclass
class TLSInfo:
    protocol_version: str | None
    not_after: _dt.datetime | None
    issuer: str | None
    days_until_expiry: int | None

    def to_dict(self) -> dict:
        return {
            "protocol_version": self.protocol_version,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "issuer": self.issuer,
            "days_until_expiry": self.days_until_expiry,
        }


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie_headers: list[str] = field(default_factory=list)
    tls: TLSInfo | None = None

    def get_header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class FetchError(RuntimeError):
    """Raised when a target could not be reached."""


def _parse_cert_not_after(cert: dict) -> _dt.datetime | None:
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        return _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


def _issuer_common_name(cert: dict) -> str | None:
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def _collect_tls_info(host: str, port: int, timeout: float) -> TLSInfo:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol_version = tls_sock.version()

    not_after = _parse_cert_not_after(cert) if cert else None
    days_left = None
    if not_after is not None:
        days_left = (not_after - _dt.datetime.now(_dt.timezone.utc)).days

    return TLSInfo(
        protocol_version=protocol_version,
        not_after=not_after,
        issuer=_issuer_common_name(cert) if cert else None,
        days_until_expiry=days_left,
    )


def live_fetch(
    url: str,
    method: str = "GET",
    timeout: float = DEFAULT_TIMEOUT,
    collect_tls: bool = True,
) -> HttpResponse:
    """Fetch ``url`` for real. Never used directly by tests (see fake transports)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError(f"Unsupported scheme: {parts.scheme!r}")

    host = parts.hostname
    if not host:
        raise FetchError(f"Could not determine host from URL: {url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=timeout)
    try:
        conn.request(method, path, headers={"User-Agent": DEFAULT_UA, "Accept": "*/*"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        set_cookie_headers = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        resp.read()  # drain so the connection can close cleanly
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(f"Failed to reach {url}: {exc}") from exc
    finally:
        conn.close()

    tls_info = None
    if parts.scheme == "https" and collect_tls:
        try:
            tls_info = _collect_tls_info(host, port, timeout)
        except (OSError, ssl.SSLError):
            tls_info = None

    return HttpResponse(
        url=url,
        status=resp.status,
        headers=headers,
        set_cookie_headers=set_cookie_headers,
        tls=tls_info,
    )
