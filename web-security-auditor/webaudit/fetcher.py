"""HTTP(S)/TLS fetching helpers.

Everything here performs a single, read-only request (GET/HEAD, or a TLS
handshake to read the certificate) against a target the caller is
authorized to test. Nothing in this module writes to the target, brute
forces anything, or attempts exploitation.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit

DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "web-security-auditor/0.1 (authorized security assessment)"


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: dict  # lowercase header name -> first value seen
    raw_header_items: list  # every (name, value) pair, duplicates preserved
    body: bytes
    error: Optional[str] = None


def _normalize_headers(raw_items) -> dict:
    out = {}
    for name, value in raw_items:
        key = name.lower()
        if key not in out:
            out[key] = value
    return out


def fetch(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    method: str = "GET",
    extra_headers: Optional[dict] = None,
) -> FetchResult:
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib_request.Request(url, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            raw_items = list(resp.getheaders())
            body = resp.read() if method != "HEAD" else b""
            return FetchResult(
                url=url,
                final_url=resp.geturl(),
                status=resp.status,
                headers=_normalize_headers(raw_items),
                raw_header_items=raw_items,
                body=body,
            )
    except HTTPError as exc:
        raw_items = list(exc.headers.items()) if exc.headers else []
        return FetchResult(
            url=url,
            final_url=url,
            status=exc.code,
            headers=_normalize_headers(raw_items),
            raw_header_items=raw_items,
            body=b"",
        )
    except (URLError, socket.timeout, OSError) as exc:
        return FetchResult(
            url=url, final_url=url, status=0, headers={}, raw_header_items=[], body=b"",
            error=str(exc),
        )


def probe_path(base_url: str, path: str, timeout: float = DEFAULT_TIMEOUT) -> FetchResult:
    """Fetch a specific path on the same host as base_url (e.g. '/.env')."""
    parts = urlsplit(base_url)
    probe_url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return fetch(probe_url, timeout=timeout, method="GET")


def probe_cors(url: str, origin: str, timeout: float = DEFAULT_TIMEOUT) -> FetchResult:
    """Re-fetch url with an arbitrary Origin header, to check CORS reflection."""
    return fetch(url, timeout=timeout, method="GET", extra_headers={"Origin": origin})


@dataclass
class TLSInfo:
    protocol: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    error: Optional[str] = None


def _parse_asn1_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def get_tls_info(hostname: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> TLSInfo:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
        return TLSInfo(
            protocol=protocol,
            not_before=_parse_asn1_date(cert.get("notBefore")) if cert else None,
            not_after=_parse_asn1_date(cert.get("notAfter")) if cert else None,
        )
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return TLSInfo(protocol=None, not_before=None, not_after=None, error=str(exc))
