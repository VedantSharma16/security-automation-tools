"""Minimal HTTP client wrapper.

Uses only the standard library (``urllib``) so the tool has zero required
dependencies and stays easy to sandbox. All network I/O funnels through
:class:`Fetcher.get`, which is the single seam the test suite mocks — every
checker module is tested against hand-built :class:`FetchResult` objects or
a fake fetcher, never real sockets.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 8.0
DEFAULT_USER_AGENT = "web-security-auditor/0.1 (+https://github.com/)"
READ_LIMIT = 262_144  # cap response bodies we buffer in memory


@dataclass
class FetchResult:
    url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie_headers: list[str] = field(default_factory=list)
    body: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None


class Fetcher:
    """Thin GET-only HTTP client. Never raises on network failure."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT):
        self.timeout = timeout
        self.user_agent = user_agent

    def get(self, url: str, extra_headers: dict[str, str] | None = None) -> FetchResult:
        request_headers = {"User-Agent": self.user_agent}
        if extra_headers:
            request_headers.update(extra_headers)
        request = urllib.request.Request(url, headers=request_headers, method="GET")

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                body = resp.read(READ_LIMIT).decode("utf-8", errors="replace")
                return FetchResult(
                    url=url,
                    status_code=resp.status,
                    headers=dict(resp.headers.items()),
                    set_cookie_headers=resp.headers.get_all("Set-Cookie") or [],
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(READ_LIMIT).decode("utf-8", errors="replace") if exc.fp else ""
            headers = dict(exc.headers.items()) if exc.headers else {}
            set_cookies = exc.headers.get_all("Set-Cookie") if exc.headers else None
            return FetchResult(
                url=url,
                status_code=exc.code,
                headers=headers,
                set_cookie_headers=set_cookies or [],
                body=body,
            )
        except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError) as exc:
            return FetchResult(url=url, status_code=None, error=str(exc))


def get_tls_info(hostname: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Open a real TLS connection and return cert/protocol/cipher details.

    Raises on connection or handshake failure; callers decide how to turn
    that into a finding (or skip TLS checks entirely for http:// targets).
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            return {
                "cert": tls_sock.getpeercert(),
                "protocol": tls_sock.version(),
                "cipher": tls_sock.cipher(),
            }
