"""Thin, transparent HTTP client used by every checker.

All requests identify the tool via a non-evasive User-Agent and use short
timeouts. Nothing in this module sends more than a GET/HEAD request or
mutates server state - the tool is strictly passive reconnaissance.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

USER_AGENT = "web-security-auditor/0.1 (+passive-recon; authorized-use-only)"
DEFAULT_TIMEOUT = 10
MAX_BODY_PREVIEW_BYTES = 2048


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int
    headers: dict
    elapsed_seconds: float
    body_preview: str = ""
    error: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    set_cookie_headers: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


def fetch(url: str, timeout: int = DEFAULT_TIMEOUT, session: requests.Session | None = None) -> FetchResult:
    """GET a URL and return a normalized FetchResult. Never raises on network errors."""
    http = session or requests
    try:
        resp = http.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return FetchResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            elapsed_seconds=0.0,
            error=str(exc),
        )

    redirect_chain = [r.url for r in resp.history]

    # A plain dict merges repeated headers (e.g. multiple Set-Cookie) with
    # commas, which corrupts cookie attribute parsing. Pull the raw list
    # from the underlying urllib3 response when available.
    try:
        set_cookie_headers = list(resp.raw.headers.getlist("Set-Cookie"))
    except AttributeError:
        single = resp.headers.get("Set-Cookie")
        set_cookie_headers = [single] if single else []

    return FetchResult(
        url=url,
        final_url=resp.url,
        status_code=resp.status_code,
        headers=dict(resp.headers),
        elapsed_seconds=resp.elapsed.total_seconds(),
        body_preview=resp.text[:MAX_BODY_PREVIEW_BYTES] if resp.text else "",
        redirect_chain=redirect_chain,
        set_cookie_headers=set_cookie_headers,
    )


def fetch_path(base_url: str, path: str, timeout: int = DEFAULT_TIMEOUT,
                session: requests.Session | None = None) -> FetchResult:
    """Fetch a specific path relative to base_url (used by exposure checks)."""
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    return fetch(url, timeout=timeout, session=session)
