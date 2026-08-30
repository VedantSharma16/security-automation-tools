"""Read-only network probes used by the recon agent.

Every function here sends at most one benign HTTP GET or TLS handshake per
call and always respects the caller's timeout, so a single unresponsive or
firewalled host cannot hang a scan. Nothing here attempts exploitation,
brute-forcing, or any write/mutating request — this is passive attack
surface enumeration only, intended for hosts you are authorized to assess.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .models import ProbeResult, TLSResult

DEFAULT_TIMEOUT = 5.0
DEFAULT_USER_AGENT = "recon-agent/0.1 (+authorized-security-assessment)"


def probe_url(url: str, timeout: float = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT) -> ProbeResult:
    """Issue a single GET request and capture status, headers, and timing."""
    request = urllib.request.Request(url, headers={"User-Agent": user_agent}, method="GET")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            elapsed_ms = (time.monotonic() - start) * 1000
            return ProbeResult(
                url=url,
                ok=True,
                status_code=response.status,
                headers=dict(response.headers.items()),
                elapsed_ms=elapsed_ms,
            )
    except urllib.error.HTTPError as exc:
        # A non-2xx/3xx response still tells us plenty (headers, server
        # banner) — treat it as a successful probe, not a failure.
        elapsed_ms = (time.monotonic() - start) * 1000
        return ProbeResult(
            url=url,
            ok=True,
            status_code=exc.code,
            headers=dict(exc.headers.items()) if exc.headers else {},
            elapsed_ms=elapsed_ms,
        )
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return ProbeResult(url=url, ok=False, error=str(exc), elapsed_ms=elapsed_ms)


def probe_tls(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> TLSResult:
    """Perform a TLS handshake and report negotiated version + certificate expiry."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                version = tls_sock.version()
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return TLSResult(host=host, port=port, ok=False, error=str(exc))

    not_after = cert.get("notAfter") if cert else None
    days_until_expiry = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_until_expiry = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    issuer = None
    if cert and cert.get("issuer"):
        issuer = ", ".join(f"{k}={v}" for tup in cert["issuer"] for k, v in tup)

    return TLSResult(
        host=host,
        port=port,
        ok=True,
        version=version,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        issuer=issuer,
    )
