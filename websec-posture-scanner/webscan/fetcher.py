"""Network layer: a single HTTP(S) GET plus an optional raw TLS handshake.

Kept deliberately thin and separate from the ``checks`` package so the
checks themselves can be unit tested against synthetic data without any
network access. This module performs two requests at most against a given
URL (the real fetch, and an optional CORS probe with a spoofed ``Origin``
header) and one TLS handshake — both read-only, non-destructive operations
safe to run against a system you're authorized to assess.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from http.client import HTTPResponse

from .models import ScanTarget, TLSInfo

DEFAULT_USER_AGENT = "websec-posture-scanner/0.1 (+https://github.com/)"
DEFAULT_CORS_TEST_ORIGIN = "https://cors-probe.invalid.example"


def fetch_target(
    url: str,
    timeout: float = 10.0,
    verify_tls: bool = True,
    send_cors_probe: bool = True,
    cors_test_origin: str = DEFAULT_CORS_TEST_ORIGIN,
) -> ScanTarget:
    """Fetch ``url`` and, optionally, re-request it with a spoofed Origin header."""

    status_code, final_url, raw_headers, elapsed_ms = _get(url, timeout, verify_tls)
    headers = _headers_dict(raw_headers)
    cookies = [v for k, v in raw_headers if k.lower() == "set-cookie"]

    cors_test_headers = None
    if send_cors_probe:
        try:
            _, _, cors_raw_headers, _ = _get(
                url, timeout, verify_tls, extra_headers={"Origin": cors_test_origin}
            )
            cors_test_headers = _headers_dict(cors_raw_headers)
        except (urllib.error.URLError, OSError, ssl.SSLError):
            cors_test_headers = None

    return ScanTarget(
        url=url,
        final_url=final_url,
        status_code=status_code,
        headers=headers,
        raw_headers=raw_headers,
        cookies=cookies,
        cors_test_headers=cors_test_headers,
        cors_test_origin=cors_test_origin if send_cors_probe else None,
        elapsed_ms=elapsed_ms,
    )


def fetch_tls_info(hostname: str, port: int = 443, timeout: float = 10.0, verify_tls: bool = True) -> TLSInfo:
    """Perform a raw TLS handshake and return certificate/protocol details."""

    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                cipher = tls_sock.cipher()
                protocol_version = tls_sock.version()
    except Exception as exc:  # noqa: BLE001 - surfaced as a Finding, not raised
        return TLSInfo(hostname=hostname, port=port, error=f"{type(exc).__name__}: {exc}")

    not_after = cert.get("notAfter")
    days_until_expiry = None
    if not_after:
        expiry_epoch = ssl.cert_time_to_seconds(not_after)
        days_until_expiry = int((expiry_epoch - time.time()) // 86400)

    return TLSInfo(
        hostname=hostname,
        port=port,
        protocol_version=protocol_version,
        cipher=cipher[0] if cipher else None,
        not_before=cert.get("notBefore"),
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        issuer=_format_name(cert.get("issuer", ())),
        subject=_format_name(cert.get("subject", ())),
        san=[value for key, value in cert.get("subjectAltName", ()) if key == "DNS"],
    )


def _get(
    url: str,
    timeout: float,
    verify_tls: bool,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, str, list[tuple[str, str]], float]:
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(url, headers=headers, method="GET")
    context = None
    if url.lower().startswith("https://") and not verify_tls:
        context = ssl._create_unverified_context()

    start = time.perf_counter()
    response: HTTPResponse
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            response.read()  # drain so keep-alive/connection cleanup behaves predictably
            elapsed_ms = (time.perf_counter() - start) * 1000
            return response.status, response.geturl(), list(response.headers.items()), elapsed_ms
    except urllib.error.HTTPError as error:
        # 4xx/5xx responses still carry headers worth auditing (e.g. an error
        # page missing security headers), so treat them as a normal fetch
        # rather than a failure.
        error.read()
        elapsed_ms = (time.perf_counter() - start) * 1000
        return error.code, error.geturl(), list(error.headers.items()), elapsed_ms


def _headers_dict(raw_headers: list[tuple[str, str]]) -> dict[str, str]:
    return {k.lower(): v for k, v in raw_headers}


def _format_name(name_tuples) -> str | None:
    if not name_tuples:
        return None
    parts = [f"{key}={value}" for rdn in name_tuples for key, value in rdn]
    return ",".join(parts) if parts else None
