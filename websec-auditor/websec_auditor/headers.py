"""HTTP security header and cookie-flag analysis.

Rules are modeled after the checks used by Mozilla Observatory / OWASP
Secure Headers Project, simplified into a self-contained rule table.
"""

from __future__ import annotations

import re

from .findings import Finding

_HSTS_MIN_MAX_AGE = 15_768_000  # ~6 months, Observatory's "good" threshold

_COOKIE_ATTR_RE = re.compile(r";\s*")


def _parse_set_cookie(raw: str) -> dict:
    parts = _COOKIE_ATTR_RE.split(raw)
    name = parts[0].split("=", 1)[0].strip() if parts else "?"
    attrs = {p.strip().lower() for p in parts[1:]}
    same_site = next(
        (p.split("=", 1)[1].strip().lower() for p in parts[1:] if p.strip().lower().startswith("samesite=")),
        None,
    )
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": same_site,
    }


def analyze_headers(headers: list[tuple[str, str]], *, is_https: bool) -> list[Finding]:
    """Analyze a response's headers and return a list of Findings.

    ``headers`` is a list of ``(name, value)`` tuples (repeated headers such
    as Set-Cookie are legal and must not be collapsed into a dict), matched
    case-insensitively. ``is_https`` gates HSTS checks, since the header is
    meaningless over plain HTTP.
    """
    findings: list[Finding] = []

    def get(name: str) -> str | None:
        target = name.lower()
        for key, value in headers:
            if key.lower() == target:
                return value
        return None

    # --- Content-Security-Policy -------------------------------------
    csp = get("content-security-policy")
    if not csp:
        findings.append(
            Finding(
                id="missing-csp",
                severity="medium",
                category="headers",
                message="No Content-Security-Policy header present.",
                recommendation=(
                    "Add a Content-Security-Policy restricting script/style/object "
                    "sources to reduce the impact of injected content (XSS)."
                ),
            )
        )
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        findings.append(
            Finding(
                id="weak-csp",
                severity="low",
                category="headers",
                message="Content-Security-Policy allows 'unsafe-inline' or 'unsafe-eval'.",
                recommendation="Avoid 'unsafe-inline'/'unsafe-eval'; use nonces or hashes instead.",
                evidence={"csp": csp},
            )
        )

    # --- Strict-Transport-Security ------------------------------------
    hsts = get("strict-transport-security")
    if is_https:
        if not hsts:
            findings.append(
                Finding(
                    id="missing-hsts",
                    severity="high",
                    category="headers",
                    message="No Strict-Transport-Security header on an HTTPS response.",
                    recommendation=(
                        "Send 'Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains' to prevent protocol downgrade attacks."
                    ),
                )
            )
        else:
            match = re.search(r"max-age=(\d+)", hsts)
            max_age = int(match.group(1)) if match else 0
            if max_age < _HSTS_MIN_MAX_AGE:
                findings.append(
                    Finding(
                        id="weak-hsts-max-age",
                        severity="low",
                        category="headers",
                        message=f"Strict-Transport-Security max-age is only {max_age}s (< 6 months).",
                        recommendation="Set max-age to at least 15768000 (6 months), ideally 31536000 (1 year).",
                        evidence={"hsts": hsts},
                    )
                )

    # --- X-Content-Type-Options ----------------------------------------
    xcto = get("x-content-type-options")
    if not xcto or xcto.strip().lower() != "nosniff":
        findings.append(
            Finding(
                id="missing-xcto",
                severity="low",
                category="headers",
                message="X-Content-Type-Options: nosniff is missing.",
                recommendation="Add 'X-Content-Type-Options: nosniff' to stop MIME-sniffing attacks.",
            )
        )

    # --- Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
    xfo = get("x-frame-options")
    has_frame_ancestors = bool(csp and "frame-ancestors" in csp)
    if not xfo and not has_frame_ancestors:
        findings.append(
            Finding(
                id="missing-clickjacking-protection",
                severity="medium",
                category="headers",
                message="No X-Frame-Options and no CSP frame-ancestors directive.",
                recommendation=(
                    "Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or a CSP "
                    "'frame-ancestors' directive to prevent clickjacking."
                ),
            )
        )

    # --- Referrer-Policy --------------------------------------------------
    if not get("referrer-policy"):
        findings.append(
            Finding(
                id="missing-referrer-policy",
                severity="low",
                category="headers",
                message="No Referrer-Policy header present.",
                recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).",
            )
        )

    # --- Permissions-Policy -----------------------------------------------
    if not get("permissions-policy"):
        findings.append(
            Finding(
                id="missing-permissions-policy",
                severity="info",
                category="headers",
                message="No Permissions-Policy header present.",
                recommendation="Consider restricting powerful browser features (camera, mic, geolocation, etc.).",
            )
        )

    # --- Information disclosure via Server / X-Powered-By ------------------
    for header_name in ("server", "x-powered-by"):
        value = get(header_name)
        if value and re.search(r"\d+\.\d+", value):
            findings.append(
                Finding(
                    id=f"version-disclosure-{header_name}",
                    severity="low",
                    category="fingerprinting",
                    message=f"{header_name.title()} header discloses a version number: {value!r}.",
                    recommendation=f"Suppress or generalize the '{header_name}' header to avoid aiding attackers.",
                    evidence={header_name: value},
                )
            )

    # --- Cookie flags ---------------------------------------------------
    for raw_cookie in [v for k, v in headers if k.lower() == "set-cookie"]:
        cookie = _parse_set_cookie(raw_cookie)
        if is_https and not cookie["secure"]:
            findings.append(
                Finding(
                    id="cookie-missing-secure",
                    severity="medium",
                    category="cookies",
                    message=f"Cookie '{cookie['name']}' is missing the Secure flag.",
                    recommendation="Set the Secure attribute on every cookie served over HTTPS.",
                    evidence={"cookie": cookie["name"]},
                )
            )
        if not cookie["httponly"]:
            findings.append(
                Finding(
                    id="cookie-missing-httponly",
                    severity="medium",
                    category="cookies",
                    message=f"Cookie '{cookie['name']}' is missing the HttpOnly flag.",
                    recommendation="Set HttpOnly on session/auth cookies to block access from JavaScript (XSS mitigation).",
                    evidence={"cookie": cookie["name"]},
                )
            )
        if cookie["samesite"] not in ("lax", "strict", "none"):
            findings.append(
                Finding(
                    id="cookie-missing-samesite",
                    severity="low",
                    category="cookies",
                    message=f"Cookie '{cookie['name']}' has no (or an invalid) SameSite attribute.",
                    recommendation="Set 'SameSite=Lax' or 'Strict' to reduce CSRF exposure.",
                    evidence={"cookie": cookie["name"]},
                )
            )
        elif cookie["samesite"] == "none" and not cookie["secure"]:
            findings.append(
                Finding(
                    id="cookie-samesite-none-without-secure",
                    severity="high",
                    category="cookies",
                    message=f"Cookie '{cookie['name']}' sets SameSite=None without Secure.",
                    recommendation="'SameSite=None' requires the Secure attribute; browsers reject it otherwise.",
                    evidence={"cookie": cookie["name"]},
                )
            )

    return findings
