"""Security-relevant HTTP response header analysis.

Each check is intentionally narrow and independently testable: given a
headers dict, return zero or more :class:`Finding` objects. ``analyze_headers``
just runs every check and flattens the results.
"""

from __future__ import annotations

import re

from .fetcher import FetchResult
from .findings import Finding

#: Headers that disclose implementation details useful for fingerprinting.
_BANNER_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


def _get(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def check_hsts(headers: dict[str, str], scheme: str) -> list[Finding]:
    if scheme != "https":
        return []
    value = _get(headers, "Strict-Transport-Security")
    if value is None:
        return [
            Finding(
                id="missing-hsts",
                category="headers",
                severity="medium",
                title="Missing Strict-Transport-Security header",
                detail="The HTTPS response did not set HSTS, so a user's browser "
                "will happily fall back to plaintext HTTP on a future visit "
                "(e.g. via a stripped link), enabling SSL-stripping attacks.",
                recommendation='Set "Strict-Transport-Security: max-age=31536000; '
                'includeSubDomains" on every HTTPS response.',
            )
        ]
    if "max-age=0" in value.replace(" ", ""):
        return [
            Finding(
                id="hsts-max-age-zero",
                category="headers",
                severity="medium",
                title="HSTS max-age is 0",
                detail=f"Strict-Transport-Security is present but disables itself: {value!r}.",
                recommendation="Set a non-zero max-age (commonly 31536000, one year).",
            )
        ]
    return []


def check_csp(headers: dict[str, str]) -> list[Finding]:
    value = _get(headers, "Content-Security-Policy")
    if value is None:
        return [
            Finding(
                id="missing-csp",
                category="headers",
                severity="medium",
                title="Missing Content-Security-Policy header",
                detail="No CSP was set, so the browser enforces no restriction on "
                "which scripts/styles/frames the page may load — a key mitigation "
                "for reflected and stored XSS is absent.",
                recommendation="Define a restrictive CSP (at minimum script-src and "
                "object-src) scoped to the origins the app actually needs.",
            )
        ]
    lowered = value.lower()
    if "unsafe-inline" in lowered and "script-src" in lowered:
        return [
            Finding(
                id="csp-unsafe-inline-script",
                category="headers",
                severity="low",
                title="CSP allows 'unsafe-inline' for scripts",
                detail="script-src includes 'unsafe-inline', which defeats most of "
                "CSP's protection against injected <script> payloads.",
                recommendation="Use a nonce- or hash-based script-src instead of "
                "'unsafe-inline'.",
            )
        ]
    return []


def check_frame_protection(headers: dict[str, str]) -> list[Finding]:
    xfo = _get(headers, "X-Frame-Options")
    csp = _get(headers, "Content-Security-Policy") or ""
    if xfo is None and "frame-ancestors" not in csp.lower():
        return [
            Finding(
                id="missing-clickjacking-protection",
                category="headers",
                severity="medium",
                title="No clickjacking protection (X-Frame-Options / frame-ancestors)",
                detail="Neither X-Frame-Options nor a CSP frame-ancestors directive "
                "was set, so the page can be embedded in a hidden <iframe> on an "
                "attacker-controlled page for clickjacking.",
                recommendation='Set "X-Frame-Options: DENY" or a CSP '
                '"frame-ancestors \'none\'" directive.',
            )
        ]
    return []


def check_content_type_options(headers: dict[str, str]) -> list[Finding]:
    value = _get(headers, "X-Content-Type-Options")
    if value is None or value.strip().lower() != "nosniff":
        return [
            Finding(
                id="missing-nosniff",
                category="headers",
                severity="low",
                title="Missing X-Content-Type-Options: nosniff",
                detail="Without nosniff, some browsers will MIME-sniff response "
                "bodies and may execute a file as HTML/JS despite a safe "
                "declared Content-Type.",
                recommendation='Set "X-Content-Type-Options: nosniff" on all responses.',
            )
        ]
    return []


def check_permissions_policy(headers: dict[str, str]) -> list[Finding]:
    if _get(headers, "Permissions-Policy") is None:
        return [
            Finding(
                id="missing-permissions-policy",
                category="headers",
                severity="info",
                title="Missing Permissions-Policy header",
                detail="No Permissions-Policy was set to restrict powerful "
                "browser features (camera, microphone, geolocation, etc.) for "
                "this origin and any embedded third-party content.",
                recommendation="Set a Permissions-Policy that disables features "
                "the application does not use.",
            )
        ]
    return []


def check_banner_disclosure(headers: dict[str, str]) -> list[Finding]:
    findings = []
    for name in _BANNER_HEADERS:
        value = _get(headers, name)
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                Finding(
                    id=f"banner-disclosure-{name.lower()}",
                    category="headers",
                    severity="info",
                    title=f"{name} discloses a version number",
                    detail=f'{name}: "{value}" — gives an attacker a head start on '
                    "matching known CVEs to the exact software version in use.",
                    recommendation=f"Suppress or genericize the {name} header at the "
                    "reverse proxy/web server config.",
                    evidence={"header": name, "value": value},
                )
            )
    return findings


def check_cookies(headers: dict[str, str], scheme: str) -> list[Finding]:
    raw = _get(headers, "Set-Cookie")
    if not raw:
        return []
    # requests folds multiple Set-Cookie headers into one comma-joined string
    # in some transports; splitting on a lookahead for "name=" is a standard
    # heuristic for finding where one cookie ends and the next begins
    # (commas can also appear inside Expires=... dates, which this avoids).
    cookies = re.split(r",\s*(?=[^;,]+=[^;,]+)", raw)
    findings = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        lowered = cookie.lower()
        missing = []
        if scheme == "https" and "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append(
                Finding(
                    id=f"cookie-missing-flags-{name.lower()}",
                    category="headers",
                    severity="medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                    title=f"Cookie '{name}' is missing {', '.join(missing)}",
                    detail=f"Set-Cookie for '{name}' lacks: {', '.join(missing)}.",
                    recommendation="Set Secure, HttpOnly, and SameSite=Lax/Strict on "
                    "every session or auth-related cookie.",
                    evidence={"cookie": name},
                )
            )
    return findings


_SCHEME_AGNOSTIC_CHECKS = (
    check_csp,
    check_frame_protection,
    check_content_type_options,
    check_permissions_policy,
    check_banner_disclosure,
)


def analyze_headers(result: FetchResult, scheme: str) -> list[Finding]:
    """Run every header check against one fetched response."""
    if not result.ok or result.headers is None:
        return []
    headers = result.headers
    findings: list[Finding] = list(check_hsts(headers, scheme))
    for check in _SCHEME_AGNOSTIC_CHECKS:
        findings += check(headers)
    findings += check_cookies(headers, scheme)
    return findings
