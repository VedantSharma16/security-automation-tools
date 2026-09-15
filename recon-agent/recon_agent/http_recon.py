"""HTTP security-header auditing and TLS certificate inspection.

Uses only the standard library (`urllib.request`, `ssl`, `socket`). Both the
HTTP fetch and the TLS certificate fetch accept an injectable callable so
tests never make a real network connection.
"""

from __future__ import annotations

import json
import os
import ssl
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.request import urlopen, Request

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

with open(os.path.join(_DATA_DIR, "security_headers.json"), encoding="utf-8") as _fh:
    RECOMMENDED_HEADERS: list[dict] = json.load(_fh)

_CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


@dataclass(frozen=True)
class HttpResult:
    url: str
    status: int | None
    headers: dict
    error: str | None

    def to_dict(self) -> dict:
        return {"url": self.url, "status": self.status, "headers": self.headers, "error": self.error}


HttpFetcher = Callable[[str, float], tuple[int, dict]]


def default_http_fetcher(url: str, timeout: float) -> tuple[int, dict]:
    request = Request(url, headers={"User-Agent": "recon-agent/0.1 (authorized-assessment)"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - deliberate recon request
        return response.status, dict(response.headers.items())


def fetch_headers(url: str, fetcher: HttpFetcher = default_http_fetcher, timeout: float = 5.0) -> HttpResult:
    try:
        status, headers = fetcher(url, timeout)
        return HttpResult(url=url, status=status, headers={k.lower(): v for k, v in headers.items()}, error=None)
    except Exception as exc:  # broad: any transport/HTTP/SSL failure is a recon "finding", not a crash
        return HttpResult(url=url, status=None, headers={}, error=str(exc))


@dataclass(frozen=True)
class HeaderFinding:
    header: str
    description: str
    severity: str

    def to_dict(self) -> dict:
        return {"header": self.header, "description": self.description, "severity": self.severity}


def audit_security_headers(headers: dict) -> list[HeaderFinding]:
    """Return one finding per recommended header that is absent from `headers`."""
    present = {k.lower() for k in headers}
    missing = []
    for entry in RECOMMENDED_HEADERS:
        if entry["header"] not in present:
            missing.append(HeaderFinding(header=entry["header"], description=entry["description"], severity=entry["severity"]))
    return missing


@dataclass(frozen=True)
class TlsResult:
    hostname: str
    port: int
    fetched: bool
    not_after: str | None
    days_remaining: int | None
    issuer: str | None
    error: str | None

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "fetched": self.fetched,
            "not_after": self.not_after,
            "days_remaining": self.days_remaining,
            "issuer": self.issuer,
            "error": self.error,
        }


CertGetter = Callable[[str, int, float], dict]


def default_cert_getter(hostname: str, port: int, timeout: float) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            return tls_sock.getpeercert()


def _format_issuer(cert: dict) -> str | None:
    issuer_rdns = cert.get("issuer")
    if not issuer_rdns:
        return None
    parts = [f"{k}={v}" for rdn in issuer_rdns for k, v in rdn]
    return ", ".join(parts)


def fetch_tls_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    cert_getter: CertGetter = default_cert_getter,
) -> TlsResult:
    try:
        cert = cert_getter(hostname, port, timeout)
    except Exception as exc:
        return TlsResult(hostname=hostname, port=port, fetched=False, not_after=None, days_remaining=None, issuer=None, error=str(exc))

    not_after = cert.get("notAfter")
    days_remaining = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, _CERT_TIME_FORMAT).replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            days_remaining = None

    return TlsResult(
        hostname=hostname,
        port=port,
        fetched=True,
        not_after=not_after,
        days_remaining=days_remaining,
        issuer=_format_issuer(cert),
        error=None,
    )
