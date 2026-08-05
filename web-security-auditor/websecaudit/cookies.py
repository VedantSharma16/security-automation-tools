"""Set-Cookie attribute checks (Secure, HttpOnly, SameSite)."""

from __future__ import annotations

from .findings import Finding


def analyze_cookies(set_cookie_headers: list[str], scheme: str) -> list[Finding]:
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        findings += _analyze_one_cookie(raw, scheme)
    return findings


def _parse_cookie(raw: str) -> tuple[str, dict]:
    """Split a raw Set-Cookie header into (cookie name, {attr_lower: value})."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs: dict = {}
    for part in parts[1:]:
        if "=" in part:
            key, _, val = part.partition("=")
            attrs[key.strip().lower()] = val.strip()
        else:
            attrs[part.strip().lower()] = True
    return name, attrs


def _analyze_one_cookie(raw: str, scheme: str) -> list[Finding]:
    name, attrs = _parse_cookie(raw)
    label = name or "<unnamed cookie>"
    findings = []

    if "secure" not in attrs and scheme == "https":
        findings.append(
            Finding(
                id="cookie-missing-secure",
                severity="high",
                category="cookie",
                message=f"Cookie '{label}' is missing the Secure attribute on an HTTPS site.",
                recommendation="Add the Secure attribute so the cookie is never sent over plain HTTP.",
            )
        )

    if "httponly" not in attrs:
        findings.append(
            Finding(
                id="cookie-missing-httponly",
                severity="medium",
                category="cookie",
                message=f"Cookie '{label}' is missing the HttpOnly attribute.",
                recommendation="Add HttpOnly unless client-side JS genuinely needs to read this cookie.",
            )
        )

    samesite = attrs.get("samesite")
    if samesite is None:
        findings.append(
            Finding(
                id="cookie-missing-samesite",
                severity="low",
                category="cookie",
                message=f"Cookie '{label}' does not set SameSite.",
                recommendation="Set SameSite=Lax (or Strict) to reduce CSRF exposure.",
            )
        )
    elif isinstance(samesite, str) and samesite.strip().lower() == "none" and "secure" not in attrs:
        findings.append(
            Finding(
                id="cookie-samesite-none-without-secure",
                severity="high",
                category="cookie",
                message=f"Cookie '{label}' sets SameSite=None without Secure (browsers will reject it).",
                recommendation="Add the Secure attribute whenever SameSite=None is used.",
            )
        )

    return findings
