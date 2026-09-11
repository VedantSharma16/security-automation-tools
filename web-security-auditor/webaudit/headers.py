"""Security-header checks, modeled on the OWASP Secure Headers Project."""

from __future__ import annotations

from typing import Optional

from .models import CheckResult

_HSTS = "strict-transport-security"
_CSP = "content-security-policy"
_XCTO = "x-content-type-options"
_XFO = "x-frame-options"
_REFERRER = "referrer-policy"
_PERMISSIONS = "permissions-policy"

_MIN_HSTS_MAX_AGE = 15552000  # 180 days


def _directive_value(header_value: str, directive: str) -> Optional[str]:
    for part in header_value.split(";"):
        part = part.strip()
        if part.lower().startswith(directive.lower()):
            return part.split("=", 1)[1].strip() if "=" in part else ""
    return None


def check_hsts(headers: dict, is_https: bool) -> CheckResult:
    if not is_https:
        return CheckResult(
            "hsts", "headers", "info", "info", "Strict-Transport-Security",
            "Target served over plain HTTP; HSTS does not apply.",
            "Serve the site over HTTPS and add Strict-Transport-Security.",
        )

    value = headers.get(_HSTS)
    if not value:
        return CheckResult(
            "hsts", "headers", "fail", "high", "Strict-Transport-Security",
            "Header is missing.",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        )

    max_age_raw = _directive_value(value, "max-age")
    try:
        max_age = int(max_age_raw) if max_age_raw else 0
    except ValueError:
        max_age = 0

    if max_age < _MIN_HSTS_MAX_AGE:
        return CheckResult(
            "hsts", "headers", "warn", "medium", "Strict-Transport-Security",
            f"Present but max-age is too low ({max_age}s).",
            "Raise max-age to at least 15552000 (180 days), ideally 31536000+.",
        )
    return CheckResult("hsts", "headers", "pass", "info", "Strict-Transport-Security",
                        f"Present: {value}", None)


def check_csp(headers: dict) -> CheckResult:
    value = headers.get(_CSP)
    if not value:
        return CheckResult(
            "csp", "headers", "fail", "high", "Content-Security-Policy",
            "Header is missing.",
            "Define a CSP restricting script/style/object sources.",
        )

    lowered = value.lower()
    risky = [tok for tok in ("unsafe-inline", "unsafe-eval") if tok in lowered]
    has_wildcard_source = any(tok == "*" for tok in lowered.replace(";", " ").split())
    if risky or has_wildcard_source:
        reason = ", ".join(risky + (["wildcard source"] if has_wildcard_source else []))
        return CheckResult(
            "csp", "headers", "warn", "medium", "Content-Security-Policy",
            f"Present but permissive ({reason}).",
            "Avoid 'unsafe-inline'/'unsafe-eval' and wildcard sources; prefer nonces/hashes.",
        )
    return CheckResult("csp", "headers", "pass", "info", "Content-Security-Policy",
                        "Present without common risky directives.", None)


def check_x_content_type_options(headers: dict) -> CheckResult:
    value = headers.get(_XCTO, "").strip().lower()
    if value == "nosniff":
        return CheckResult("x-content-type-options", "headers", "pass", "info",
                            "X-Content-Type-Options", "Set to 'nosniff'.", None)
    return CheckResult(
        "x-content-type-options", "headers", "fail", "low", "X-Content-Type-Options",
        "Missing or not set to 'nosniff'.",
        "Add 'X-Content-Type-Options: nosniff'.",
    )


def check_frame_options(headers: dict) -> CheckResult:
    csp = headers.get(_CSP, "")
    if "frame-ancestors" in csp.lower():
        return CheckResult("x-frame-options", "headers", "pass", "info", "X-Frame-Options",
                            "Clickjacking protection provided via CSP 'frame-ancestors'.", None)

    value = headers.get(_XFO, "").strip().lower()
    if value in ("deny", "sameorigin"):
        return CheckResult("x-frame-options", "headers", "pass", "info", "X-Frame-Options",
                            f"Set to '{value}'.", None)
    return CheckResult(
        "x-frame-options", "headers", "fail", "medium", "X-Frame-Options",
        "Missing, and no CSP 'frame-ancestors' directive found.",
        "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    )


def check_referrer_policy(headers: dict) -> CheckResult:
    value = headers.get(_REFERRER, "").strip()
    if not value:
        return CheckResult(
            "referrer-policy", "headers", "warn", "low", "Referrer-Policy",
            "Header is missing.",
            "Add e.g. 'Referrer-Policy: strict-origin-when-cross-origin'.",
        )
    if value.lower() == "unsafe-url":
        return CheckResult(
            "referrer-policy", "headers", "warn", "low", "Referrer-Policy",
            "Set to 'unsafe-url', which leaks the full URL cross-origin.",
            "Use a stricter policy such as 'strict-origin-when-cross-origin'.",
        )
    return CheckResult("referrer-policy", "headers", "pass", "info", "Referrer-Policy",
                        f"Set to '{value}'.", None)


def check_permissions_policy(headers: dict) -> CheckResult:
    value = headers.get(_PERMISSIONS, "").strip()
    if not value:
        return CheckResult(
            "permissions-policy", "headers", "warn", "low", "Permissions-Policy",
            "Header is missing.",
            "Restrict unused browser features (camera, microphone, geolocation, etc.).",
        )
    return CheckResult("permissions-policy", "headers", "pass", "info", "Permissions-Policy",
                        f"Set to '{value}'.", None)


def run_all(headers: dict, is_https: bool) -> list[CheckResult]:
    return [
        check_hsts(headers, is_https),
        check_csp(headers),
        check_x_content_type_options(headers),
        check_frame_options(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
    ]
