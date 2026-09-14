"""Cookie attribute checks: Secure, HttpOnly, SameSite."""

from __future__ import annotations

from http.cookies import SimpleCookie

from http_audit.fetcher import HttpResponse
from http_audit.report import Finding


def _cookie_name(set_cookie_header: str) -> str:
    return set_cookie_header.split("=", 1)[0].strip() or "(unnamed)"


def check_cookies(response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    is_https = response.url.startswith("https://")

    for raw in response.set_cookie_headers:
        name = _cookie_name(raw)
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # pragma: no cover - defensive, malformed cookie strings
            continue
        if not jar:
            continue
        morsel = next(iter(jar.values()))
        cookie_findings: list[Finding] = []

        if is_https and not morsel["secure"]:
            cookie_findings.append(
                Finding(
                    "cookies",
                    f"Cookie '{name}' missing Secure",
                    "high",
                    f"Cookie '{name}' is set over HTTPS without the Secure flag; it can be sent over plain HTTP.",
                    "Add the Secure attribute to every cookie on an HTTPS site.",
                )
            )

        if not morsel["httponly"]:
            cookie_findings.append(
                Finding(
                    "cookies",
                    f"Cookie '{name}' missing HttpOnly",
                    "medium",
                    f"Cookie '{name}' lacks HttpOnly and is readable via client-side JavaScript (XSS exfiltration risk).",
                    "Add the HttpOnly attribute unless the cookie must be read by JavaScript.",
                )
            )

        samesite = (morsel["samesite"] or "").strip().lower()
        if samesite not in ("strict", "lax"):
            cookie_findings.append(
                Finding(
                    "cookies",
                    f"Cookie '{name}' weak SameSite",
                    "low",
                    f"Cookie '{name}' has SameSite='{morsel['samesite'] or 'unset'}', offering weak CSRF protection.",
                    "Set SameSite=Lax or SameSite=Strict (use None only with Secure and a documented cross-site need).",
                )
            )

        if cookie_findings:
            findings.extend(cookie_findings)
        else:
            findings.append(Finding("cookies", f"Cookie '{name}'", "pass", "Secure, HttpOnly, and SameSite are all set correctly."))

    if not response.set_cookie_headers:
        findings.append(Finding("cookies", "Cookies", "info", "No Set-Cookie headers observed on this response."))

    return findings
