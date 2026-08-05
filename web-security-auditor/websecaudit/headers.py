"""Security header checks (HSTS, CSP, X-Frame-Options, etc.).

Each ``_check_*`` function inspects the response headers already collected
by ``fetcher.fetch()`` and returns zero or more ``Finding`` objects. Pure
functions over plain dicts/strings — no I/O — so they're trivial to unit
test with fixture headers.
"""

from __future__ import annotations

import re

from .findings import Finding

_HSTS_MIN_MAX_AGE = 15552000  # 180 days, the commonly recommended floor


def analyze_headers(headers: dict, scheme: str, redirect_chain: list) -> list[Finding]:
    """``headers`` must have lower-cased keys (see ``fetcher.fetch``)."""
    findings: list[Finding] = []
    findings += _check_transport_security(headers, scheme, redirect_chain)
    findings += _check_csp(headers)
    findings += _check_content_type_options(headers)
    findings += _check_frame_protection(headers)
    findings += _check_referrer_policy(headers)
    findings += _check_permissions_policy(headers)
    findings += _check_info_disclosure(headers)
    return findings


def _check_transport_security(headers: dict, scheme: str, redirect_chain: list) -> list[Finding]:
    if scheme != "https":
        upgraded = any(
            url.startswith("https://") for url, _status in redirect_chain
        )
        if upgraded:
            return []
        return [
            Finding(
                id="plaintext-http",
                severity="high",
                category="transport",
                message="Site was served over plain HTTP and never redirected to HTTPS.",
                recommendation="Serve all traffic over HTTPS and redirect HTTP to HTTPS.",
            )
        ]

    hsts = headers.get("strict-transport-security")
    if not hsts:
        return [
            Finding(
                id="missing-hsts",
                severity="medium",
                category="header",
                message="Strict-Transport-Security header is missing.",
                recommendation=(
                    "Add 'Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains' to force HTTPS on repeat visits."
                ),
            )
        ]

    out = []
    match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    if max_age < _HSTS_MIN_MAX_AGE:
        out.append(
            Finding(
                id="weak-hsts-max-age",
                severity="low",
                category="header",
                message=f"HSTS max-age is {max_age}s, below the recommended 180 days.",
                recommendation="Set max-age to at least 15552000 (180 days), ideally 31536000.",
            )
        )
    if "includesubdomains" not in hsts.lower():
        out.append(
            Finding(
                id="hsts-missing-includesubdomains",
                severity="info",
                category="header",
                message="HSTS header does not set includeSubDomains.",
                recommendation="Add includeSubDomains if all subdomains also support HTTPS.",
            )
        )
    return out


def _check_csp(headers: dict) -> list[Finding]:
    csp = headers.get("content-security-policy")
    if not csp:
        return [
            Finding(
                id="missing-csp",
                severity="medium",
                category="header",
                message="Content-Security-Policy header is missing.",
                recommendation=(
                    "Define a CSP with at least default-src/script-src to mitigate XSS "
                    "and data-injection attacks."
                ),
            )
        ]
    out = []
    lowered = csp.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        out.append(
            Finding(
                id="csp-unsafe-directives",
                severity="medium",
                category="header",
                message="CSP allows 'unsafe-inline' and/or 'unsafe-eval'.",
                recommendation="Remove unsafe-inline/unsafe-eval; use nonces/hashes for scripts.",
            )
        )
    if "default-src" not in lowered and "script-src" not in lowered:
        out.append(
            Finding(
                id="csp-missing-src-directive",
                severity="low",
                category="header",
                message="CSP does not define default-src or script-src.",
                recommendation="Add an explicit default-src or script-src directive.",
            )
        )
    return out


def _check_content_type_options(headers: dict) -> list[Finding]:
    value = headers.get("x-content-type-options", "").strip().lower()
    if value != "nosniff":
        return [
            Finding(
                id="missing-x-content-type-options",
                severity="low",
                category="header",
                message="X-Content-Type-Options: nosniff header is missing.",
                recommendation="Add 'X-Content-Type-Options: nosniff' to block MIME-sniffing.",
            )
        ]
    return []


def _check_frame_protection(headers: dict) -> list[Finding]:
    xfo = headers.get("x-frame-options", "").strip().lower()
    csp = headers.get("content-security-policy", "").lower()
    if xfo in {"deny", "sameorigin"} or "frame-ancestors" in csp:
        return []
    return [
        Finding(
            id="missing-clickjacking-protection",
            severity="medium",
            category="header",
            message="Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
            recommendation=(
                "Add 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP frame-ancestors "
                "directive to prevent clickjacking."
            ),
        )
    ]


def _check_referrer_policy(headers: dict) -> list[Finding]:
    rp = headers.get("referrer-policy", "").strip().lower()
    if not rp:
        return [
            Finding(
                id="missing-referrer-policy",
                severity="low",
                category="header",
                message="Referrer-Policy header is missing.",
                recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
            )
        ]
    if rp == "unsafe-url":
        return [
            Finding(
                id="permissive-referrer-policy",
                severity="low",
                category="header",
                message="Referrer-Policy is set to 'unsafe-url', leaking full URLs cross-origin.",
                recommendation="Use 'strict-origin-when-cross-origin' or 'no-referrer' instead.",
            )
        ]
    return []


def _check_permissions_policy(headers: dict) -> list[Finding]:
    if not headers.get("permissions-policy"):
        return [
            Finding(
                id="missing-permissions-policy",
                severity="info",
                category="header",
                message="Permissions-Policy header is not set.",
                recommendation="Consider restricting powerful browser features (camera, mic, geolocation).",
            )
        ]
    return []


def _check_info_disclosure(headers: dict) -> list[Finding]:
    out = []
    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        out.append(
            Finding(
                id="server-header-discloses-version",
                severity="info",
                category="header",
                message=f"Server header discloses software/version: '{server}'.",
                recommendation="Suppress or generalize the Server header to reduce fingerprinting.",
            )
        )
    if headers.get("x-powered-by"):
        out.append(
            Finding(
                id="x-powered-by-disclosure",
                severity="info",
                category="header",
                message=f"X-Powered-By header discloses backend technology: '{headers['x-powered-by']}'.",
                recommendation="Remove the X-Powered-By header.",
            )
        )
    return out
