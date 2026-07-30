"""Orchestrates a full recon pass: headers, sensitive-path discovery, fingerprinting.

Safety note: this tool sends real HTTP requests to the target. It refuses to
run unless the caller explicitly asserts authorization
(`authorized=True` / `--i-have-authorization`). Only use it against systems
you own or have written permission to test.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .fingerprint import fingerprint
from .headers import check_security_headers
from .models import Finding, ScanResult
from .paths import DEFAULT_SENSITIVE_PATHS, discover_sensitive_paths

DEFAULT_TIMEOUT = 5.0
DEFAULT_DELAY = 0.0
DEFAULT_USER_AGENT = "webrecon/0.1 (+authorized-security-testing)"


class AuthorizationError(RuntimeError):
    """Raised when a scan is attempted without an explicit authorization flag."""


class InvalidTargetError(ValueError):
    """Raised when the target URL is malformed or uses an unsupported scheme."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise InvalidTargetError(f"unsupported scheme in target URL: {target!r} (use http/https)")
    if not parsed.netloc:
        raise InvalidTargetError(f"target URL has no host: {target!r}")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}" or target


def _requests_get(session: requests.Session, timeout: float):
    def _get(url: str, req_timeout: float) -> tuple[int, bytes]:
        resp = session.get(url, timeout=req_timeout, allow_redirects=False)
        return resp.status_code, resp.content

    return _get


def scan_target(
    target: str,
    authorized: bool,
    timeout: float = DEFAULT_TIMEOUT,
    delay: float = DEFAULT_DELAY,
    path_wordlist: list[tuple] | None = None,
    session: requests.Session | None = None,
) -> ScanResult:
    """Run header, sensitive-path, and fingerprint checks against `target`.

    Raises `AuthorizationError` unless `authorized=True` is passed, and
    `InvalidTargetError` if the URL is malformed or non-HTTP(S).
    """
    if not authorized:
        raise AuthorizationError(
            "scan_target() requires authorized=True: only scan systems you own "
            "or have explicit written permission to test."
        )

    base_url = _validate_target(target)
    started_at = _now()
    findings: list[Finding] = []
    errors: list[str] = []

    owns_session = session is None
    session = session or requests.Session()
    session.headers.setdefault("User-Agent", DEFAULT_USER_AGENT)

    try:
        try:
            response = session.get(base_url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            errors.append(f"initial request to {base_url} failed: {exc}")
            return ScanResult(
                target=base_url, started_at=started_at, finished_at=_now(), errors=errors
            )

        is_https = urlparse(response.url).scheme == "https"
        set_cookie_headers = []
        try:
            set_cookie_headers = response.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            raw_sc = response.headers.get("Set-Cookie")
            if raw_sc:
                set_cookie_headers = [raw_sc]

        findings.extend(
            check_security_headers(response.headers, is_https, set_cookie_headers)
        )

        body_text = response.text if response.encoding or response.content else ""
        cookie_names = [c.name for c in session.cookies] + [
            sc.split("=", 1)[0].strip() for sc in set_cookie_headers if "=" in sc
        ]
        findings.extend(fingerprint(response.headers, body_text, cookie_names))

        findings.extend(
            discover_sensitive_paths(
                base_url,
                _requests_get(session, timeout),
                paths=path_wordlist if path_wordlist is not None else DEFAULT_SENSITIVE_PATHS,
                delay=delay,
                timeout=timeout,
            )
        )
    finally:
        if owns_session:
            session.close()

    return ScanResult(
        target=base_url,
        started_at=started_at,
        finished_at=_now(),
        findings=findings,
        errors=errors,
    )
