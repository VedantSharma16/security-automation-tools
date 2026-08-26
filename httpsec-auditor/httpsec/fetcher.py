"""Network I/O boundary: issues passive GET/OPTIONS requests over HTTP(S).

Only used for its side effects (talking to the network); every other module
in this package operates on the plain data structures it returns, which is
what makes them unit-testable without a live target.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from .models import FetchResult

DEFAULT_USER_AGENT = "httpsec-auditor/0.1 (+passive security scan)"


def _ssl_context(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Records redirects instead of silently following them forever."""

    def __init__(self) -> None:
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(
    url: str,
    timeout: float = 10.0,
    extra_headers: dict | None = None,
    insecure: bool = False,
    method: str = "GET",
) -> FetchResult:
    """Fetch a URL, following redirects, and return a normalized result."""
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    redirect_handler = _NoRedirectHandler()
    opener = urllib.request.build_opener(
        redirect_handler, urllib.request.HTTPSHandler(context=_ssl_context(insecure))
    )

    req = urllib.request.Request(url, headers=headers, method=method)
    start = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            elapsed_ms = (time.monotonic() - start) * 1000
            resp_headers = dict(resp.headers.items())
            set_cookies = resp.headers.get_all("Set-Cookie") or []
            return FetchResult(
                url=url,
                final_url=resp.geturl(),
                status_code=resp.status,
                headers=resp_headers,
                set_cookies=list(set_cookies),
                redirect_chain=redirect_handler.chain,
                elapsed_ms=elapsed_ms,
            )
    except urllib.error.HTTPError as exc:
        # Non-2xx/3xx is still a valid response with headers worth auditing.
        elapsed_ms = (time.monotonic() - start) * 1000
        resp_headers = dict(exc.headers.items()) if exc.headers else {}
        set_cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
        return FetchResult(
            url=url,
            final_url=exc.url or url,
            status_code=exc.code,
            headers=resp_headers,
            set_cookies=list(set_cookies or []),
            redirect_chain=redirect_handler.chain,
            elapsed_ms=elapsed_ms,
        )


def fetch_with_origin(
    url: str, origin: str, timeout: float = 10.0, insecure: bool = False
) -> FetchResult:
    """Fetch a URL while sending an arbitrary Origin header, to probe CORS
    policy the way a cross-site page in a victim's browser would."""
    return fetch(
        url,
        timeout=timeout,
        extra_headers={"Origin": origin},
        insecure=insecure,
    )
