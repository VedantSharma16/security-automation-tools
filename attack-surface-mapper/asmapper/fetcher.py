"""Minimal stdlib-only HTTP GET client used by every recon module.

Deliberately built on ``urllib`` rather than a third-party HTTP library so
the tool has zero required dependencies. Every network call in the package
goes through :func:`fetch`, which makes it trivial to swap in a fake for
tests (no real network access is used anywhere in the test suite).
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "attack-surface-mapper/0.1 (+authorized-security-assessment)"
DEFAULT_TIMEOUT = 8.0
MAX_BODY_BYTES = 1_000_000


@dataclass
class FetchResult:
    url: str
    status: int | None
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT, method: str = "GET") -> FetchResult:
    """Issue a single GET (or other simple) request and normalize the result.

    Never raises: transport failures (DNS, refused connection, timeout, TLS
    errors) are captured on ``FetchResult.error`` instead, so callers can
    treat every recon step uniformly.
    """
    request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body_bytes = response.read(MAX_BODY_BYTES)
            elapsed_ms = (time.monotonic() - start) * 1000
            charset = response.headers.get_content_charset() or "utf-8"
            return FetchResult(
                url=url,
                status=response.status,
                headers=dict(response.getheaders()),
                body=body_bytes.decode(charset, errors="replace"),
                elapsed_ms=elapsed_ms,
            )
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        body_bytes = exc.read(MAX_BODY_BYTES) if exc.fp else b""
        return FetchResult(
            url=url,
            status=exc.code,
            headers=dict(exc.headers.items()) if exc.headers else {},
            body=body_bytes.decode("utf-8", errors="replace"),
            elapsed_ms=elapsed_ms,
        )
    except Exception as exc:  # noqa: BLE001 - network/DNS/TLS failures are all "unreachable"
        elapsed_ms = (time.monotonic() - start) * 1000
        return FetchResult(url=url, status=None, elapsed_ms=elapsed_ms, error=str(exc))
