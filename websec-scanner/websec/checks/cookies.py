"""Set-Cookie flag analysis (Secure / HttpOnly / SameSite)."""

from __future__ import annotations

from http.cookies import SimpleCookie

from ..models import Finding, Severity

CHECK_NAME = "cookies"


def _parse_set_cookie_headers(raw_headers: list[str]) -> list[dict]:
    """Parse a list of raw 'Set-Cookie' header values into flag dicts.

    Each header is parsed independently (a single `SimpleCookie` would drop
    duplicate cookie names), so we build one small `SimpleCookie` per header.
    """
    parsed = []
    for raw in raw_headers:
        jar: SimpleCookie = SimpleCookie()
        jar.load(raw)
        for name, morsel in jar.items():
            parsed.append(
                {
                    "name": name,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or "",
                    "raw": raw,
                }
            )
    return parsed


def check_cookies(url: str, raw_set_cookie_headers: list[str], is_https: bool) -> list[Finding]:
    """Flag session/auth-looking cookies missing Secure/HttpOnly/SameSite."""
    findings: list[Finding] = []

    for cookie in _parse_set_cookie_headers(raw_set_cookie_headers):
        name = cookie["name"]

        if is_https and not cookie["secure"]:
            findings.append(
                Finding(
                    check=CHECK_NAME,
                    severity=Severity.MEDIUM,
                    title=f"Cookie '{name}' missing Secure flag",
                    url=url,
                    detail="Cookie set over HTTPS without the 'Secure' flag can "
                    "still be sent over a plaintext HTTP connection.",
                    evidence=cookie["raw"],
                    recommendation=f"Add the 'Secure' attribute to the '{name}' cookie.",
                )
            )

        if not cookie["httponly"]:
            findings.append(
                Finding(
                    check=CHECK_NAME,
                    severity=Severity.MEDIUM,
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    url=url,
                    detail="Without 'HttpOnly', client-side JavaScript (including "
                    "injected via XSS) can read this cookie's value.",
                    evidence=cookie["raw"],
                    recommendation=f"Add the 'HttpOnly' attribute to the '{name}' cookie.",
                )
            )

        samesite = cookie["samesite"].lower()
        if samesite not in ("lax", "strict"):
            findings.append(
                Finding(
                    check=CHECK_NAME,
                    severity=Severity.LOW,
                    title=f"Cookie '{name}' missing or weak SameSite attribute",
                    url=url,
                    detail=f"SameSite is '{cookie['samesite'] or '(not set)'}'; "
                    "browsers default to 'Lax' but explicit is safer, and "
                    "'None' requires 'Secure' and disables CSRF protection "
                    "the attribute would otherwise provide.",
                    evidence=cookie["raw"],
                    recommendation=f"Set 'SameSite=Lax' or 'SameSite=Strict' on the "
                    f"'{name}' cookie unless cross-site delivery is required.",
                )
            )

    return findings
