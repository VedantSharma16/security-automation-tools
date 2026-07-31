"""Minimal HTTP(S) fetcher used to gather response headers for auditing.

Uses only the standard library so the tool has zero runtime dependencies.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "web-security-auditor/0.1 (+https://github.com/VedantSharma16/security-automation-tools)"

HeaderList = List[Tuple[str, str]]


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: HeaderList = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def get(self, name: str) -> Optional[str]:
        """First header value matching ``name``, case-insensitively."""
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def get_all(self, name: str) -> List[str]:
        """All header values matching ``name`` (e.g. repeated Set-Cookie)."""
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]


class _RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        self.chain: List[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT) -> FetchResult:
    """Issue a single GET request, following redirects, and capture headers.

    Never raises: network and HTTP errors are captured on ``FetchResult.error``
    so a batch audit of many URLs can continue past unreachable hosts.
    """
    tracker = _RedirectTracker()
    opener = urllib.request.build_opener(tracker)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    start = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            elapsed_ms = (time.monotonic() - start) * 1000
            return FetchResult(
                url=url,
                final_url=response.geturl(),
                status=response.status,
                headers=list(response.getheaders()),
                redirect_chain=tracker.chain,
                elapsed_ms=elapsed_ms,
            )
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        headers = list(exc.headers.items()) if exc.headers else []
        return FetchResult(
            url=url,
            final_url=exc.geturl() or url,
            status=exc.code,
            headers=headers,
            redirect_chain=tracker.chain,
            elapsed_ms=elapsed_ms,
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return FetchResult(
            url=url,
            final_url=url,
            status=0,
            headers=[],
            redirect_chain=tracker.chain,
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )
