"""Security-relevant HTTP response header analysis.

Pure functions over plain dicts/strings, so they can be unit tested without
any network I/O — the CLI is responsible for fetching the response and
handing this module the headers it received.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class HeaderFinding:
    header: str
    severity: str
    present: bool
    value: str | None
    message: str


def _validate_hsts(value: str) -> str | None:
    if "max-age=" not in value.lower():
        return "Strict-Transport-Security is present but missing 'max-age'."
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if match and int(match.group(1)) < 15552000:  # 180 days
        return f"Strict-Transport-Security max-age is short ({match.group(1)}s, recommend >= 180 days)."
    return None


def _validate_csp(value: str) -> str | None:
    if re.search(r"unsafe-inline|unsafe-eval", value, re.IGNORECASE):
        return "Content-Security-Policy allows 'unsafe-inline' or 'unsafe-eval', weakening XSS protection."
    return None


def _validate_nosniff(value: str) -> str | None:
    if value.strip().lower() != "nosniff":
        return f"X-Content-Type-Options has an unexpected value: {value!r} (expected 'nosniff')."
    return None


def _validate_xfo(value: str) -> str | None:
    if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return f"X-Frame-Options has an unrecognized value: {value!r}."
    return None


# (header name, severity if missing entirely, validator for present-but-maybe-weak
# values, recommendation shown to the user).
CHECKS = (
    (
        "Strict-Transport-Security",
        "high",
        _validate_hsts,
        "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
    ),
    (
        "Content-Security-Policy",
        "medium",
        _validate_csp,
        "Define a restrictive Content-Security-Policy to mitigate XSS/data injection.",
    ),
    (
        "X-Content-Type-Options",
        "medium",
        _validate_nosniff,
        "Set 'X-Content-Type-Options: nosniff'.",
    ),
    (
        "X-Frame-Options",
        "medium",
        _validate_xfo,
        "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or a CSP 'frame-ancestors' directive).",
    ),
    (
        "Referrer-Policy",
        "low",
        None,
        "Set a 'Referrer-Policy' (e.g. 'strict-origin-when-cross-origin') to limit referrer leakage.",
    ),
    (
        "Permissions-Policy",
        "low",
        None,
        "Set a 'Permissions-Policy' to restrict powerful browser features (camera, geolocation, etc).",
    ),
)

# Headers that leak implementation details useful for an attacker's recon phase.
INFO_DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


def _lower_map(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def analyze_headers(headers: dict) -> list:
    """Check `headers` (a response-header dict) against a baseline of
    recommended security headers, returning one finding per check.
    """
    lower_headers = _lower_map(headers)
    findings = []

    for name, missing_severity, validator, recommendation in CHECKS:
        value = lower_headers.get(name.lower())
        if value is None:
            findings.append(
                HeaderFinding(
                    header=name,
                    severity=missing_severity,
                    present=False,
                    value=None,
                    message=f"Missing recommended header '{name}'. {recommendation}",
                )
            )
            continue

        problem = validator(value) if validator else None
        if problem:
            findings.append(
                HeaderFinding(header=name, severity="medium", present=True, value=value, message=problem)
            )
        else:
            findings.append(
                HeaderFinding(
                    header=name, severity="info", present=True, value=value, message=f"'{name}' looks fine."
                )
            )

    for name in INFO_DISCLOSURE_HEADERS:
        value = lower_headers.get(name.lower())
        if value:
            findings.append(
                HeaderFinding(
                    header=name,
                    severity="low",
                    present=True,
                    value=value,
                    message=f"'{name}: {value}' discloses server/framework details useful for attacker recon.",
                )
            )

    return findings


def analyze_cookies(set_cookie_headers: list) -> list:
    """Flag cookies missing the Secure/HttpOnly/SameSite flags.

    `set_cookie_headers` should be the *raw, unmerged* list of Set-Cookie
    header values (e.g. from `response.raw.headers.get_all("Set-Cookie")`)
    since commas inside cookie attributes like `Expires` make a single
    comma-joined header unsafe to split on.
    """
    findings = []
    for raw in set_cookie_headers or []:
        name = raw.split("=", 1)[0].strip()
        lower = raw.lower()
        missing = [flag for flag, token in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if token not in lower]

        if missing:
            findings.append(
                HeaderFinding(
                    header="Set-Cookie",
                    severity="medium",
                    present=True,
                    value=raw,
                    message=f"Cookie '{name}' is missing flag(s): {', '.join(missing)}.",
                )
            )
        else:
            findings.append(
                HeaderFinding(
                    header="Set-Cookie",
                    severity="info",
                    present=True,
                    value=raw,
                    message=f"Cookie '{name}' sets Secure, HttpOnly, and SameSite.",
                )
            )
    return findings
