"""Thin, injectable HTTP client used by every scan module.

Every other module talks to :class:`Fetcher`, never to ``requests``
directly, so tests can swap in an in-process server (or a fake session)
without touching the scan logic itself.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

DEFAULT_TIMEOUT = 6.0
DEFAULT_USER_AGENT = "web-recon-auditor/0.1 (+https://github.com/; authorized-testing-only)"


@dataclass
class FetchResult:
    """Normalized view of an HTTP response (or the lack of one)."""

    url: str
    ok: bool
    status_code: int | None = None
    headers: dict[str, str] | None = None
    body: str = ""
    error: str | None = None

    @property
    def content_length(self) -> int:
        return len(self.body)


def normalize_base_url(target: str) -> str:
    """Ensure a target has a scheme and no trailing path/query junk."""
    if "://" not in target:
        target = f"https://{target}"
    parts = urlsplit(target)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


class Fetcher:
    """Wraps a ``requests.Session`` with sane defaults and no raised exceptions.

    Network/DNS/TLS failures are captured into :class:`FetchResult.error`
    instead of propagating, so a scan of an unreachable or misconfigured
    host still produces a usable (partial) report.
    """

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool = True,
    ):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session.headers.setdefault("User-Agent", user_agent)

    def get(self, url: str, allow_redirects: bool = True) -> FetchResult:
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            return FetchResult(url=url, ok=False, error=str(exc))
        return FetchResult(
            url=url,
            ok=True,
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()},
            body=resp.text or "",
        )

    def get_path(self, base_url: str, path: str) -> FetchResult:
        return self.get(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))

    def baseline_404(self, base_url: str) -> FetchResult:
        """Probe a guaranteed-nonexistent path to learn the host's soft-404 shape.

        Many apps return HTTP 200 with a catch-all "not found" page for any
        unmatched route, which would otherwise make every sensitive-path probe
        look like a hit. Comparing against this baseline filters that noise.
        """
        canary = f"__webrecon_canary_{uuid.uuid4().hex}__"
        return self.get_path(base_url, canary)
