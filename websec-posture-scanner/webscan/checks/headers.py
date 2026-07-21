"""OWASP Secure Headers Project style checks for response security headers."""

from __future__ import annotations

import re

from ..models import Finding, ScanTarget

# Minimum recommended Strict-Transport-Security max-age, in seconds (~180 days).
_HSTS_MIN_MAX_AGE = 15_552_000

_RISKY_CSP_TOKENS = ("unsafe-inline", "unsafe-eval")


def check_security_headers(target: ScanTarget) -> list[Finding]:
    findings: list[Finding] = []
    is_https = target.final_url.lower().startswith("https://")

    findings.extend(_check_hsts(target, is_https))
    findings.extend(_check_csp(target))
    findings.extend(_check_content_type_options(target))
    findings.extend(_check_frame_protection(target))
    findings.extend(_check_referrer_policy(target))
    findings.extend(_check_permissions_policy(target))
    return findings


def _check_hsts(target: ScanTarget, is_https: bool) -> list[Finding]:
    if not is_https:
        return []

    hsts = target.get_header("strict-transport-security")
    if hsts is None:
        return [
            Finding(
                id="headers-hsts-missing",
                title="Missing Strict-Transport-Security header",
                severity="high",
                category="headers",
                description=(
                    "The site is served over HTTPS but does not send "
                    "Strict-Transport-Security, so browsers will still allow a "
                    "plaintext HTTP connection and are vulnerable to SSL-stripping "
                    "downgrade attacks on the first request."
                ),
                remediation=(
                    "Send `Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload` on every HTTPS response."
                ),
            )
        ]

    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    if max_age < _HSTS_MIN_MAX_AGE:
        return [
            Finding(
                id="headers-hsts-weak-max-age",
                title="Strict-Transport-Security max-age is too low",
                severity="medium",
                category="headers",
                description=(
                    f"HSTS max-age is {max_age} seconds, below the recommended "
                    f"minimum of {_HSTS_MIN_MAX_AGE} (~180 days)."
                ),
                remediation="Raise max-age to at least 31536000 (1 year).",
                evidence=hsts,
            )
        ]
    return []


def _check_csp(target: ScanTarget) -> list[Finding]:
    csp = target.get_header("content-security-policy")
    if csp is None:
        return [
            Finding(
                id="headers-csp-missing",
                title="Missing Content-Security-Policy header",
                severity="high",
                category="headers",
                description=(
                    "No Content-Security-Policy is set, leaving the page without "
                    "browser-enforced defenses against cross-site scripting and "
                    "data-injection attacks."
                ),
                remediation=(
                    "Define a restrictive CSP, e.g. `default-src 'self'`, and "
                    "tighten `script-src`/`style-src` to avoid `unsafe-inline` "
                    "and `unsafe-eval`."
                ),
            )
        ]

    lowered = csp.lower()
    risky = [token for token in _RISKY_CSP_TOKENS if token in lowered]
    if risky:
        return [
            Finding(
                id="headers-csp-unsafe-directives",
                title="Content-Security-Policy allows unsafe script execution",
                severity="medium",
                category="headers",
                description=(
                    "The CSP includes " + ", ".join(risky) + ", which largely "
                    "defeats CSP's protection against XSS."
                ),
                remediation=(
                    "Remove 'unsafe-inline'/'unsafe-eval' in favor of nonces, "
                    "hashes, or externalized scripts."
                ),
                evidence=csp,
            )
        ]
    return []


def _check_content_type_options(target: ScanTarget) -> list[Finding]:
    value = target.get_header("x-content-type-options")
    if value is None or value.strip().lower() != "nosniff":
        return [
            Finding(
                id="headers-content-type-options-missing",
                title="Missing X-Content-Type-Options: nosniff",
                severity="medium",
                category="headers",
                description=(
                    "Without `nosniff`, older browsers may MIME-sniff response "
                    "bodies and execute content that wasn't served as a script."
                ),
                remediation="Send `X-Content-Type-Options: nosniff` on all responses.",
                evidence=value or "",
            )
        ]
    return []


def _check_frame_protection(target: ScanTarget) -> list[Finding]:
    xfo = target.get_header("x-frame-options")
    csp = target.get_header("content-security-policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo is None and not has_frame_ancestors:
        return [
            Finding(
                id="headers-clickjacking-protection-missing",
                title="No clickjacking protection (X-Frame-Options / frame-ancestors)",
                severity="medium",
                category="headers",
                description=(
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive "
                    "is set, so the page can be embedded in a hostile iframe for "
                    "clickjacking attacks."
                ),
                remediation=(
                    "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) or a CSP "
                    "`frame-ancestors` directive."
                ),
            )
        ]
    return []


def _check_referrer_policy(target: ScanTarget) -> list[Finding]:
    if target.get_header("referrer-policy") is None:
        return [
            Finding(
                id="headers-referrer-policy-missing",
                title="Missing Referrer-Policy header",
                severity="low",
                category="headers",
                description=(
                    "Without an explicit Referrer-Policy, full URLs (which may "
                    "include sensitive query parameters) can leak to third "
                    "parties via the Referer header on outbound links."
                ),
                remediation=(
                    "Send `Referrer-Policy: strict-origin-when-cross-origin` "
                    "or stricter."
                ),
            )
        ]
    return []


def _check_permissions_policy(target: ScanTarget) -> list[Finding]:
    if target.get_header("permissions-policy") is None:
        return [
            Finding(
                id="headers-permissions-policy-missing",
                title="Missing Permissions-Policy header",
                severity="info",
                category="headers",
                description=(
                    "No Permissions-Policy is set, so the page does not "
                    "explicitly opt out of powerful browser features "
                    "(camera, microphone, geolocation, etc.) it doesn't use."
                ),
                remediation=(
                    "Send a Permissions-Policy that disables unused features, "
                    "e.g. `camera=(), microphone=(), geolocation=()`."
                ),
            )
        ]
    return []
