"""Security header and cookie-attribute checks, modeled on the OWASP Secure
Headers Project and Mozilla Observatory rule set.
"""

from __future__ import annotations

import re
from typing import List

from .fetcher import FetchResult
from .models import Finding, Severity, Status

_VERSION_RE = re.compile(r"\d+\.\d+")


def check_hsts(response: FetchResult, is_https: bool = True) -> Finding:
    value = response.get("Strict-Transport-Security")
    if not is_https:
        return Finding(
            "hsts", "Strict-Transport-Security", Status.WARN, Severity.LOW,
            "Site was reached over plain HTTP; browsers ignore HSTS on non-HTTPS responses.",
            "Serve the site over HTTPS and redirect all HTTP traffic there.",
        )
    if value is None:
        return Finding(
            "hsts", "Strict-Transport-Security", Status.FAIL, Severity.HIGH,
            "No Strict-Transport-Security header was sent.",
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on every HTTPS response.",
        )
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    if max_age < 15552000:  # 180 days
        return Finding(
            "hsts", "Strict-Transport-Security", Status.WARN, Severity.MEDIUM,
            f"HSTS present but max-age is only {max_age}s (recommended >= 15552000s / 180 days).",
            "Raise max-age to at least 15552000 seconds and add includeSubDomains.",
        )
    return Finding(
        "hsts", "Strict-Transport-Security", Status.PASS, Severity.INFO,
        f"HSTS present with max-age={max_age}.", None,
    )


def check_csp(response: FetchResult) -> Finding:
    value = response.get("Content-Security-Policy")
    if value is None:
        return Finding(
            "csp", "Content-Security-Policy", Status.FAIL, Severity.HIGH,
            "No Content-Security-Policy header was sent.",
            "Define a CSP that restricts script, style, and object sources to trusted origins.",
        )
    lowered = value.lower()
    weak_tokens = [t for t in ("unsafe-inline", "unsafe-eval", "*") if t in lowered]
    if weak_tokens:
        return Finding(
            "csp", "Content-Security-Policy", Status.WARN, Severity.MEDIUM,
            f"CSP present but contains weak directives: {', '.join(weak_tokens)}.",
            "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces or hashes instead.",
        )
    return Finding("csp", "Content-Security-Policy", Status.PASS, Severity.INFO, "CSP present with no obviously weak directives.", None)


def check_x_content_type_options(response: FetchResult) -> Finding:
    value = response.get("X-Content-Type-Options")
    if value is None or value.strip().lower() != "nosniff":
        return Finding(
            "x-content-type-options", "X-Content-Type-Options", Status.FAIL, Severity.MEDIUM,
            "X-Content-Type-Options is missing or not set to 'nosniff'.",
            "Send 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing based attacks.",
        )
    return Finding("x-content-type-options", "X-Content-Type-Options", Status.PASS, Severity.INFO, "nosniff set.", None)


def check_frame_protection(response: FetchResult) -> Finding:
    xfo = response.get("X-Frame-Options")
    csp = (response.get("Content-Security-Policy") or "").lower()
    if xfo is not None and xfo.strip().lower() in ("deny", "sameorigin"):
        return Finding("frame-protection", "Clickjacking Protection", Status.PASS, Severity.INFO, f"X-Frame-Options: {xfo}.", None)
    if "frame-ancestors" in csp:
        return Finding("frame-protection", "Clickjacking Protection", Status.PASS, Severity.INFO, "CSP frame-ancestors directive present.", None)
    return Finding(
        "frame-protection", "Clickjacking Protection", Status.FAIL, Severity.MEDIUM,
        "Neither X-Frame-Options nor a CSP frame-ancestors directive was found.",
        "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive to prevent clickjacking.",
    )


def check_referrer_policy(response: FetchResult) -> Finding:
    value = response.get("Referrer-Policy")
    if value is None:
        return Finding(
            "referrer-policy", "Referrer-Policy", Status.FAIL, Severity.LOW,
            "No Referrer-Policy header was sent.",
            "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).",
        )
    if value.strip().lower() == "unsafe-url":
        return Finding(
            "referrer-policy", "Referrer-Policy", Status.WARN, Severity.LOW,
            "Referrer-Policy is set to 'unsafe-url', which leaks the full URL cross-origin.",
            "Use 'strict-origin-when-cross-origin' or a same-origin policy instead.",
        )
    return Finding("referrer-policy", "Referrer-Policy", Status.PASS, Severity.INFO, f"Referrer-Policy: {value}.", None)


def check_permissions_policy(response: FetchResult) -> Finding:
    value = response.get("Permissions-Policy")
    if value is None:
        return Finding(
            "permissions-policy", "Permissions-Policy", Status.WARN, Severity.LOW,
            "No Permissions-Policy header was sent.",
            "Send a Permissions-Policy header to restrict powerful browser features (camera, geolocation, etc).",
        )
    return Finding("permissions-policy", "Permissions-Policy", Status.PASS, Severity.INFO, "Permissions-Policy present.", None)


def check_server_disclosure(response: FetchResult) -> Finding:
    disclosing = []
    for header_name in ("Server", "X-Powered-By"):
        value = response.get(header_name)
        if value and _VERSION_RE.search(value):
            disclosing.append(f"{header_name}: {value}")
    if disclosing:
        return Finding(
            "server-disclosure", "Server Version Disclosure", Status.WARN, Severity.LOW,
            "Response discloses software/version information: " + "; ".join(disclosing),
            "Remove or generalize the Server/X-Powered-By headers at the reverse proxy.",
        )
    return Finding("server-disclosure", "Server Version Disclosure", Status.PASS, Severity.INFO, "No version-identifying Server/X-Powered-By headers.", None)


def _parse_cookie_attributes(set_cookie_value: str) -> dict:
    parts = [p.strip() for p in set_cookie_value.split(";")]
    attrs = {"secure": False, "httponly": False, "samesite": None}
    for part in parts[1:]:
        lowered = part.lower()
        if lowered == "secure":
            attrs["secure"] = True
        elif lowered == "httponly":
            attrs["httponly"] = True
        elif lowered.startswith("samesite"):
            attrs["samesite"] = part.split("=", 1)[1].strip() if "=" in part else "Lax"
    return attrs


def check_cookies(response: FetchResult) -> Finding:
    cookies = response.get_all("Set-Cookie")
    if not cookies:
        return Finding("cookie-flags", "Cookie Attributes", Status.PASS, Severity.INFO, "No Set-Cookie headers to evaluate.", None)

    problems = []
    for raw in cookies:
        name = raw.split("=", 1)[0]
        attrs = _parse_cookie_attributes(raw)
        missing = []
        if not attrs["secure"]:
            missing.append("Secure")
        if not attrs["httponly"]:
            missing.append("HttpOnly")
        if not attrs["samesite"]:
            missing.append("SameSite")
        if missing:
            problems.append(f"{name} missing {', '.join(missing)}")

    if problems:
        return Finding(
            "cookie-flags", "Cookie Attributes", Status.FAIL, Severity.HIGH,
            "One or more cookies are missing security attributes: " + "; ".join(problems),
            "Set Secure, HttpOnly, and SameSite on every session/auth cookie.",
        )
    return Finding("cookie-flags", "Cookie Attributes", Status.PASS, Severity.INFO, "All cookies set Secure, HttpOnly, and SameSite.", None)


# check_hsts is scheme-aware and invoked separately by evaluate_headers.
CHECKS = (
    check_csp,
    check_x_content_type_options,
    check_frame_protection,
    check_referrer_policy,
    check_permissions_policy,
    check_server_disclosure,
    check_cookies,
)


def evaluate_headers(response: FetchResult) -> List[Finding]:
    """Run every header/cookie check against a fetched response."""
    is_https = response.final_url.lower().startswith("https://")
    findings = [check_hsts(response, is_https=is_https)]
    findings.extend(check(response) for check in CHECKS)
    return findings
