"""Passive HTTP recon: security-header audit and robots.txt/sitemap checks.

Network access goes through an injectable ``urllib.request`` opener so the
whole module is testable with a fake opener instead of live HTTP calls.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 5.0
USER_AGENT = "recon-agent/0.1 (+passive, authorized-testing-only)"

# Security headers a hardened public web server is expected to send, and
# what their absence means for an attacker doing passive recon.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing — downgrade/SSL-stripping attacks are not mitigated",
    "content-security-policy": "CSP missing — no mitigation against reflected/stored XSS",
    "x-content-type-options": "X-Content-Type-Options missing — MIME-sniffing may be possible",
    "x-frame-options": "X-Frame-Options missing — clickjacking is not mitigated",
    "referrer-policy": "Referrer-Policy missing — full URLs may leak to third parties via Referer",
}

# Response headers that reveal stack/version info useful to an attacker.
FINGERPRINT_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


@dataclass
class HttpFinding:
    url: str
    status: int | None = None
    headers: dict = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    fingerprint: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class RobotsFinding:
    url: str
    fetched: bool = False
    disallowed_paths: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    error: str | None = None


def _build_opener(opener: "urllib.request.OpenerDirector | None") -> urllib.request.OpenerDirector:
    return opener if opener is not None else urllib.request.build_opener()


def fetch_headers(
    url: str,
    opener: "urllib.request.OpenerDirector | None" = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> HttpFinding:
    """Fetch ``url`` and audit response headers for security posture."""
    opener = _build_opener(opener)
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            headers = {k.lower(): v for k, v in response.getheaders()}
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return HttpFinding(url=url, error=str(exc))

    missing = [header for header in SECURITY_HEADERS if header not in headers]
    fingerprint = {h: headers[h] for h in FINGERPRINT_HEADERS if h in headers}
    return HttpFinding(
        url=url,
        status=status,
        headers=headers,
        missing_security_headers=missing,
        fingerprint=fingerprint,
    )


def fetch_robots(
    base_url: str,
    opener: "urllib.request.OpenerDirector | None" = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> RobotsFinding:
    """Fetch ``base_url``'s robots.txt and extract Disallow/Sitemap entries.

    A restrictive robots.txt is itself recon signal: disallowed paths often
    point straight at admin panels or staging areas an attacker wouldn't
    otherwise have found.
    """
    opener = _build_opener(opener)
    robots_url = base_url.rstrip("/") + "/robots.txt"
    request = urllib.request.Request(robots_url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return RobotsFinding(url=robots_url, fetched=False)
        return RobotsFinding(url=robots_url, error=f"HTTP {exc.code}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return RobotsFinding(url=robots_url, error=str(exc))

    disallowed, sitemaps = [], []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "disallow" and value:
            disallowed.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)

    return RobotsFinding(url=robots_url, fetched=True, disallowed_paths=disallowed, sitemaps=sitemaps)
