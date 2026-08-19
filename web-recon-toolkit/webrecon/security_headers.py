"""Grade HTTP response security headers against a baseline security posture.

Loosely modeled on Mozilla Observatory's approach: a small set of weighted
checks (missing hardening headers, verbose banners, insecure cookies)
collapse into a 0-100 score and an A-F letter grade.
"""

from __future__ import annotations

# name -> (weight, https_only, advice)
SECURITY_HEADERS: dict[str, tuple[int, bool, str]] = {
    "content-security-policy": (25, False, "mitigates XSS/data-injection by restricting content sources"),
    "strict-transport-security": (20, True, "prevents protocol downgrade / SSL-stripping attacks"),
    "x-content-type-options": (15, False, "prevents MIME-sniffing of served content"),
    "x-frame-options": (15, False, "prevents clickjacking via iframe embedding"),
    "permissions-policy": (15, False, "restricts access to sensitive browser features/APIs"),
    "referrer-policy": (10, False, "limits referrer leakage to third parties"),
}

INFO_LEAK_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def letter_grade(pct: int) -> str:
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 40:
        return "D"
    return "F"


def _cookie_findings(set_cookie: str) -> list[dict]:
    findings = []
    lowered = set_cookie.lower()
    if "secure" not in lowered:
        findings.append({
            "header": "set-cookie", "severity": "medium",
            "message": "Cookie is missing the Secure attribute and may be sent over plaintext HTTP.",
        })
    if "httponly" not in lowered:
        findings.append({
            "header": "set-cookie", "severity": "medium",
            "message": "Cookie is missing the HttpOnly attribute and is readable via JavaScript (XSS exfiltration risk).",
        })
    if "samesite" not in lowered:
        findings.append({
            "header": "set-cookie", "severity": "low",
            "message": "Cookie is missing the SameSite attribute and may be sent on cross-site requests (CSRF risk).",
        })
    return findings


def grade_headers(headers: dict[str, str], is_https: bool) -> dict:
    """Score a response's headers. Returns {score, grade, findings}."""
    normalized = {k.lower(): v for k, v in headers.items()}
    findings: list[dict] = []
    score = 0
    max_score = 0

    for name, (weight, https_only, advice) in SECURITY_HEADERS.items():
        if https_only and not is_https:
            continue
        max_score += weight
        if name in normalized:
            score += weight
        else:
            findings.append({
                "header": name, "severity": "medium",
                "message": f"Missing '{name}' header -- {advice}.",
            })

    for name in INFO_LEAK_HEADERS:
        if name in normalized:
            findings.append({
                "header": name, "severity": "low",
                "message": f"'{name}: {normalized[name]}' discloses server/framework version to attackers.",
            })

    if "set-cookie" in normalized:
        findings.extend(_cookie_findings(normalized["set-cookie"]))

    pct = round(100 * score / max_score) if max_score else 100
    return {"score": pct, "grade": letter_grade(pct), "findings": findings}
