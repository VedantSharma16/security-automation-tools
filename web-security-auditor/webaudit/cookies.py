"""Session-cookie attribute checks (Secure / HttpOnly / SameSite)."""

from __future__ import annotations

from .models import CheckResult


def _parse_set_cookie(raw: str) -> tuple[str, set[str], str | None]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: set[str] = set()
    samesite = None
    for part in parts[1:]:
        if "=" in part:
            key, val = part.split("=", 1)
            key = key.strip().lower()
            attrs.add(key)
            if key == "samesite":
                samesite = val.strip()
        elif part:
            attrs.add(part.strip().lower())
    return name, attrs, samesite


def analyze_cookies(set_cookie_values: list[str], is_https: bool) -> list[CheckResult]:
    results = []
    for raw in set_cookie_values:
        name, attrs, samesite = _parse_set_cookie(raw)
        issues = []
        severity = "info"

        if is_https and "secure" not in attrs:
            issues.append("missing 'Secure'")
            severity = "high"
        if "httponly" not in attrs:
            issues.append("missing 'HttpOnly'")
            if severity != "high":
                severity = "medium"
        if samesite is None:
            issues.append("missing 'SameSite'")
            if severity not in ("high",):
                severity = "medium"
        elif samesite.lower() == "none" and "secure" not in attrs:
            issues.append("'SameSite=None' without 'Secure'")
            severity = "high"

        if issues:
            results.append(CheckResult(
                id=f"cookie:{name}", category="cookies", status="fail", severity=severity,
                title=f"Cookie '{name}'",
                detail=f"Cookie '{name}' is {', '.join(issues)}.",
                remediation="Set Secure, HttpOnly, and an explicit SameSite attribute on "
                            "session/auth cookies.",
            ))
        else:
            results.append(CheckResult(
                id=f"cookie:{name}", category="cookies", status="pass", severity="info",
                title=f"Cookie '{name}'",
                detail=f"Sets Secure, HttpOnly, and SameSite={samesite}.",
                remediation=None,
            ))
    return results
