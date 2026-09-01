"""Thin, injectable HTTP layer.

Every network call in the project goes through this module so the rest of
the codebase -- and all of the test suite -- can run without touching a
real socket by swapping in a fake ``opener``.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

USER_AGENT = "websec-auditor/0.1 (+passive recon; see README for scope)"
DEFAULT_TIMEOUT = 8.0


@dataclass
class FetchResult:
    request_url: str
    final_url: str
    status: int
    # A list of (name, value) tuples, NOT a dict: headers like Set-Cookie are
    # legally repeated, and collapsing them into a dict would silently drop
    # every cookie but the last one.
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    def header(self, name: str, default: str | None = None) -> str | None:
        """Case-insensitive lookup of the first value for a header."""
        target = name.lower()
        for key, value in self.headers:
            if key.lower() == target:
                return value
        return default

    def all_headers(self, name: str) -> list[str]:
        """Return every value for a (possibly repeated) header, e.g. Set-Cookie."""
        target = name.lower()
        return [v for k, v in self.headers if k.lower() == target]

    def headers_dict(self) -> dict[str, str]:
        """First-value-wins view, for callers that only care about single-value headers."""
        result: dict[str, str] = {}
        for key, value in self.headers:
            result.setdefault(key, value)
        return result


def normalize_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")
    return parsed.geturl()


def fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    opener: "urllib.request.OpenerDirector | None" = None,
    method: str = "GET",
) -> FetchResult:
    """Fetch a URL and return headers/body. Never raises for HTTP-level errors."""
    url = normalize_url(url)
    request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    build = opener.open if opener is not None else urllib.request.urlopen

    try:
        with build(request, timeout=timeout) as response:
            headers = list(response.headers.items())
            body = response.read(1_000_000)  # cap: this is a header/config audit, not a crawler
            return FetchResult(
                request_url=url,
                final_url=response.geturl(),
                status=response.status,
                headers=headers,
                body=body,
            )
    except urllib.error.HTTPError as exc:
        headers = list(exc.headers.items()) if exc.headers else []
        return FetchResult(
            request_url=url,
            final_url=exc.geturl() if hasattr(exc, "geturl") else url,
            status=exc.code,
            headers=headers,
            body=b"",
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return FetchResult(
            request_url=url,
            final_url=url,
            status=0,
            headers=[],
            body=b"",
            error=str(exc),
        )


def fetch_well_known(
    base_url: str,
    paths: list[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    opener: "urllib.request.OpenerDirector | None" = None,
) -> dict[str, FetchResult]:
    """Fetch a small, fixed set of standard, publicly-documented paths
    (robots.txt, security.txt, ...). This performs the same kind of request
    any browser or search-engine crawler makes -- it does not probe for
    hidden or sensitive files.
    """
    parsed = urlparse(normalize_url(base_url))
    root = f"{parsed.scheme}://{parsed.netloc}"
    results = {}
    for path in paths:
        target = root.rstrip("/") + "/" + path.lstrip("/")
        results[path] = fetch(target, timeout=timeout, opener=opener)
    return results
