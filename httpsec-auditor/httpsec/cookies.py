"""Analysis of Set-Cookie response headers for missing security flags."""

from __future__ import annotations

from .models import Finding

# Heuristic: cookies whose name suggests they carry session/auth material
# get a slightly stricter bar than incidental cookies (e.g. analytics IDs).
SENSITIVE_NAME_HINTS = ("sess", "auth", "token", "jwt", "login", "sso", "csrf", "xsrf")


def _parse_cookie(raw: str) -> tuple[str, dict]:
    """Parse one Set-Cookie header value into (name, {flag_or_attr: value})."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return "", {}
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[part.strip().lower()] = True
    return name, attrs


def _is_sensitive(name: str) -> bool:
    lname = name.lower()
    return any(hint in lname for hint in SENSITIVE_NAME_HINTS)


def analyze_cookies(set_cookie_headers: list[str], scheme: str = "https") -> list[Finding]:
    findings: list[Finding] = []

    for raw in set_cookie_headers:
        name, attrs = _parse_cookie(raw)
        if not name:
            continue
        sensitive = _is_sensitive(name)

        if "secure" not in attrs and scheme == "https":
            findings.append(
                Finding(
                    id="cookie-missing-secure",
                    category="cookies",
                    severity="high" if sensitive else "medium",
                    title=f"Cookie '{name}' is missing the Secure flag",
                    description="Without Secure, the cookie can be sent over a plaintext HTTP connection, exposing it to network eavesdroppers.",
                    remediation=f"Add `Secure` to the Set-Cookie attributes for '{name}'.",
                    evidence=raw,
                )
            )

        if "httponly" not in attrs:
            findings.append(
                Finding(
                    id="cookie-missing-httponly",
                    category="cookies",
                    severity="high" if sensitive else "medium",
                    title=f"Cookie '{name}' is missing the HttpOnly flag",
                    description="Without HttpOnly, client-side JavaScript (including injected via XSS) can read this cookie's value.",
                    remediation=f"Add `HttpOnly` to the Set-Cookie attributes for '{name}' unless a script genuinely needs to read it.",
                    evidence=raw,
                )
            )

        samesite = attrs.get("samesite")
        if samesite is None:
            findings.append(
                Finding(
                    id="cookie-missing-samesite",
                    category="cookies",
                    severity="medium",
                    title=f"Cookie '{name}' has no SameSite attribute",
                    description="Without SameSite, the cookie is sent on cross-site requests, widening exposure to CSRF.",
                    remediation=f"Add `SameSite=Lax` (or `Strict` for auth cookies) to '{name}'.",
                    evidence=raw,
                )
            )
        elif str(samesite).lower() == "none" and "secure" not in attrs:
            findings.append(
                Finding(
                    id="cookie-samesite-none-without-secure",
                    category="cookies",
                    severity="high",
                    title=f"Cookie '{name}' uses SameSite=None without Secure",
                    description="`SameSite=None` requires `Secure`; browsers reject the cookie without it, but a misconfigured deployment leaves it inconsistently applied and easy to regress into an insecure state.",
                    remediation=f"Pair `SameSite=None` on '{name}' with `Secure`.",
                    evidence=raw,
                )
            )

    return findings
