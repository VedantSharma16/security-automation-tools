"""Fetch a URL over HTTP(S) and normalize the response for downstream analysis.

The network call is behind an injectable `Transport` callable so every other
module in the pipeline can be tested (and reasoned about) without ever making
a real request -- `default_transport` is the only place that touches a socket.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

DEFAULT_USER_AGENT = "webrecon/0.1 (authorized-security-testing)"
MAX_BODY_BYTES = 1_000_000  # cap reads so a hostile/huge response can't exhaust memory


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    error: str | None = None


Transport = Callable[[str, float], HttpResponse]


def default_transport(url: str, timeout: float) -> HttpResponse:
    """Real transport: issue a GET request with urllib. Only http/https allowed."""
    request = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 (scheme validated below)
            body_bytes = resp.read(MAX_BODY_BYTES)
            elapsed_ms = (time.monotonic() - start) * 1000
            charset = resp.headers.get_content_charset() or "utf-8"
            return HttpResponse(
                url=url,
                status_code=resp.status,
                headers=dict(resp.headers.items()),
                body=body_bytes.decode(charset, errors="replace"),
                elapsed_ms=elapsed_ms,
            )
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        body_bytes = exc.read(MAX_BODY_BYTES) if exc.fp else b""
        headers = dict(exc.headers.items()) if exc.headers else {}
        return HttpResponse(
            url=url,
            status_code=exc.code,
            headers=headers,
            body=body_bytes.decode("utf-8", errors="replace"),
            elapsed_ms=elapsed_ms,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return HttpResponse(
            url=url, status_code=0, headers={}, body="", elapsed_ms=elapsed_ms, error=str(exc)
        )


def fetch(url: str, timeout: float = 5.0, transport: Transport = default_transport) -> HttpResponse:
    """Fetch `url` through `transport` (real network by default, fake in tests)."""
    if not url.lower().startswith(("http://", "https://")):
        return HttpResponse(
            url=url, status_code=0, headers={}, body="", elapsed_ms=0.0,
            error=f"unsupported URL scheme (only http/https are allowed): {url!r}",
        )
    return transport(url, timeout)
