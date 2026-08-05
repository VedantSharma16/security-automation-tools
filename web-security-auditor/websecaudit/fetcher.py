"""Network boundary of the tool.

Everything else in this package (headers.py, cookies.py, tls.py, grading.py,
report.py) operates on the plain-data results defined here, so the analysis
logic can be fully unit tested with fixtures and never has to touch a real
socket. Only this module talks to the network.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = (
    "web-security-auditor/0.1 "
    "(+https://github.com/VedantSharma16/security-automation-tools)"
)


@dataclass
class TLSInfo:
    protocol_version: str | None = None
    cipher: str | None = None
    not_after: datetime | None = None
    days_until_expiry: int | None = None
    error: str | None = None


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    scheme: str
    headers: dict = field(default_factory=dict)  # lower-cased header names
    set_cookie_headers: list = field(default_factory=list)
    redirect_chain: list = field(default_factory=list)  # [(url, status_code), ...]
    tls: TLSInfo | None = None
    elapsed_ms: float | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def fetch(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    probe_tls: bool = True,
    user_agent: str = DEFAULT_USER_AGENT,
) -> FetchResult:
    """Fetch ``url`` and, for https targets, probe the TLS handshake directly.

    A direct socket probe (rather than trusting whatever ``requests``/urllib3
    negotiated) is used for the TLS report because it lets us record the
    negotiated protocol version and certificate expiry even when
    ``verify_tls=False`` is used to reach hosts with self-signed certs.
    """
    scheme = urlsplit(url).scheme or "http"
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
            headers={"User-Agent": user_agent},
        )
    except requests.RequestException as exc:
        return FetchResult(
            requested_url=url,
            final_url=url,
            status_code=0,
            scheme=scheme,
            error=str(exc),
        )

    headers = {k.lower(): v for k, v in resp.headers.items()}
    set_cookie_headers = _extract_set_cookie_headers(resp)
    redirect_chain = [(r.url, r.status_code) for r in resp.history]
    final_scheme = urlsplit(resp.url).scheme

    tls_info = None
    if probe_tls and final_scheme == "https":
        parts = urlsplit(resp.url)
        tls_info = probe_tls_connection(
            parts.hostname, parts.port or 443, timeout=timeout, verify=verify_tls
        )

    return FetchResult(
        requested_url=url,
        final_url=resp.url,
        status_code=resp.status_code,
        scheme=final_scheme,
        headers=headers,
        set_cookie_headers=set_cookie_headers,
        redirect_chain=redirect_chain,
        tls=tls_info,
        elapsed_ms=resp.elapsed.total_seconds() * 1000,
    )


def _extract_set_cookie_headers(resp) -> list:
    """Return every Set-Cookie header value (there can be more than one)."""
    raw_headers = getattr(resp.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "get_all"):
        values = raw_headers.get_all("Set-Cookie")
        if values:
            return list(values)
    single = resp.headers.get("Set-Cookie")
    return [single] if single else []


def probe_tls_connection(hostname: str, port: int, timeout: float, verify: bool = True) -> TLSInfo:
    try:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                not_after = _parse_cert_not_after(cert.get("notAfter") if cert else None)
                days_until_expiry = None
                if not_after is not None:
                    days_until_expiry = (not_after - datetime.now(timezone.utc)).days
                return TLSInfo(
                    protocol_version=tls_sock.version(),
                    cipher=cipher[0] if cipher else None,
                    not_after=not_after,
                    days_until_expiry=days_until_expiry,
                )
    except (OSError, ssl.SSLError) as exc:
        return TLSInfo(error=str(exc))


def _parse_cert_not_after(not_after_str: str | None) -> datetime | None:
    if not not_after_str:
        return None
    return datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
