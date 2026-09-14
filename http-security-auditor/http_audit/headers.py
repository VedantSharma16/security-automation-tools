"""Security header checks, modeled loosely on the OWASP Secure Headers Project."""

from __future__ import annotations

from http_audit.fetcher import HttpResponse
from http_audit.report import Finding

_UNSAFE_CSP_TOKENS = ("unsafe-inline", "unsafe-eval")


def check_headers(response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    findings.append(_check_hsts(response))
    findings.append(_check_csp(response))
    findings.append(_check_x_content_type_options(response))
    findings.append(_check_frame_protection(response))
    findings.append(_check_referrer_policy(response))
    findings.append(_check_permissions_policy(response))
    findings.extend(_check_server_disclosure(response))
    return findings


def _check_hsts(response: HttpResponse) -> Finding:
    value = response.get_header("strict-transport-security")
    if value is None:
        return Finding(
            "headers",
            "Strict-Transport-Security",
            "high",
            "HSTS header is missing; the site does not instruct browsers to require HTTPS.",
            "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (add 'preload' once verified).",
        )
    max_age = 0
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                max_age = 0
    if max_age < 31536000:
        return Finding(
            "headers",
            "Strict-Transport-Security",
            "medium",
            f"HSTS max-age is {max_age} seconds, below the recommended one year (31536000).",
            "Increase max-age to at least 31536000 seconds.",
        )
    return Finding("headers", "Strict-Transport-Security", "pass", f"HSTS present with max-age={max_age}.")


def _check_csp(response: HttpResponse) -> Finding:
    value = response.get_header("content-security-policy")
    if value is None:
        return Finding(
            "headers",
            "Content-Security-Policy",
            "high",
            "No Content-Security-Policy header; the site has no defense-in-depth against XSS/injection.",
            "Define a CSP that restricts script/style/object sources to trusted origins.",
        )
    lowered = value.lower()
    unsafe = [tok for tok in _UNSAFE_CSP_TOKENS if tok in lowered]
    if unsafe:
        return Finding(
            "headers",
            "Content-Security-Policy",
            "medium",
            f"CSP present but weakened by: {', '.join(unsafe)}.",
            "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for required inline scripts.",
        )
    return Finding("headers", "Content-Security-Policy", "pass", "CSP present without unsafe-inline/unsafe-eval.")


def _check_x_content_type_options(response: HttpResponse) -> Finding:
    value = response.get_header("x-content-type-options")
    if value is None or value.strip().lower() != "nosniff":
        return Finding(
            "headers",
            "X-Content-Type-Options",
            "low",
            "X-Content-Type-Options is missing or not 'nosniff'; browsers may MIME-sniff responses.",
            "Set 'X-Content-Type-Options: nosniff'.",
        )
    return Finding("headers", "X-Content-Type-Options", "pass", "nosniff is set.")


def _check_frame_protection(response: HttpResponse) -> Finding:
    xfo = response.get_header("x-frame-options")
    csp = response.get_header("content-security-policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo is None and not has_frame_ancestors:
        return Finding(
            "headers",
            "Clickjacking protection",
            "medium",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
            "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) or add 'frame-ancestors' to the CSP.",
        )
    return Finding("headers", "Clickjacking protection", "pass", "Framing is restricted via X-Frame-Options or CSP.")


def _check_referrer_policy(response: HttpResponse) -> Finding:
    value = response.get_header("referrer-policy")
    if value is None:
        return Finding(
            "headers",
            "Referrer-Policy",
            "low",
            "Referrer-Policy is missing; full URLs (possibly with sensitive query params) may leak on outbound links.",
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
        )
    return Finding("headers", "Referrer-Policy", "pass", f"Referrer-Policy set to '{value}'.")


def _check_permissions_policy(response: HttpResponse) -> Finding:
    value = response.get_header("permissions-policy")
    if value is None:
        return Finding(
            "headers",
            "Permissions-Policy",
            "info",
            "Permissions-Policy is missing; powerful browser features (camera, geolocation, etc.) are not restricted.",
            "Set a Permissions-Policy that disables features the site does not use.",
        )
    return Finding("headers", "Permissions-Policy", "pass", "Permissions-Policy is set.")


def _check_server_disclosure(response: HttpResponse) -> list[Finding]:
    findings = []
    for header_name in ("server", "x-powered-by"):
        value = response.get_header(header_name)
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                Finding(
                    "headers",
                    f"{header_name.title()} disclosure",
                    "low",
                    f"'{header_name}' header reveals version information: '{value}'.",
                    f"Suppress or generalize the '{header_name}' header to avoid fingerprinting.",
                )
            )
    return findings
