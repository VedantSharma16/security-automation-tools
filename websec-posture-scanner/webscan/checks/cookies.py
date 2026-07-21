"""Set-Cookie attribute checks (Secure / HttpOnly / SameSite)."""

from __future__ import annotations

from ..models import Finding, ScanTarget

_SENSITIVE_NAME_HINTS = ("sess", "auth", "token", "sid", "login", "csrf", "jwt")


def check_cookies(target: ScanTarget) -> list[Finding]:
    is_https = target.final_url.lower().startswith("https://")
    findings: list[Finding] = []

    for raw_cookie in target.cookies:
        name, attrs = _parse_set_cookie(raw_cookie)
        sensitive = any(hint in name.lower() for hint in _SENSITIVE_NAME_HINTS)
        same_site = attrs.get("samesite", "").lower()

        if is_https and "secure" not in attrs:
            findings.append(
                Finding(
                    id=f"cookie-missing-secure-{name}",
                    title=f'Cookie "{name}" missing the Secure attribute',
                    severity="high" if sensitive else "medium",
                    category="cookies",
                    description=(
                        f'Cookie "{name}" is set over HTTPS without `Secure`, so it '
                        "could still be sent over a downgraded plaintext connection."
                    ),
                    remediation=f'Add `Secure` to the "{name}" Set-Cookie attributes.',
                    evidence=raw_cookie,
                )
            )

        if "httponly" not in attrs:
            findings.append(
                Finding(
                    id=f"cookie-missing-httponly-{name}",
                    title=f'Cookie "{name}" missing the HttpOnly attribute',
                    severity="medium" if sensitive else "low",
                    category="cookies",
                    description=(
                        f'Cookie "{name}" can be read by JavaScript via '
                        "`document.cookie`, making it a target for theft through XSS."
                    ),
                    remediation=f'Add `HttpOnly` to the "{name}" Set-Cookie attributes.',
                    evidence=raw_cookie,
                )
            )

        if same_site == "none" and "secure" not in attrs:
            findings.append(
                Finding(
                    id=f"cookie-samesite-none-without-secure-{name}",
                    title=f'Cookie "{name}" uses SameSite=None without Secure',
                    severity="high",
                    category="cookies",
                    description=(
                        "`SameSite=None` requires `Secure`; modern browsers reject "
                        "the cookie entirely without it, which is also a strong "
                        "signal the cookie attributes were not deliberately set."
                    ),
                    remediation="Add `Secure` alongside `SameSite=None`.",
                    evidence=raw_cookie,
                )
            )
        elif not same_site:
            findings.append(
                Finding(
                    id=f"cookie-missing-samesite-{name}",
                    title=f'Cookie "{name}" missing the SameSite attribute',
                    severity="low",
                    category="cookies",
                    description=(
                        f'Cookie "{name}" has no SameSite attribute, so the browser '
                        "default applies, which varies by browser/version. Without an "
                        "explicit value the cookie may be sent on cross-site requests, "
                        "weakening CSRF defenses."
                    ),
                    remediation=f'Set `SameSite=Lax` (or `Strict`) on the "{name}" cookie.',
                    evidence=raw_cookie,
                )
            )

    return findings


def _parse_set_cookie(raw_cookie: str) -> tuple[str, dict[str, str]]:
    """Split a raw Set-Cookie header value into (cookie_name, {attr_lower: value})."""

    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""

    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            attrs[part.strip().lower()] = ""
    return name, attrs
