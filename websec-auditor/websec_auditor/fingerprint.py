"""Lightweight technology fingerprinting from headers, cookies, and body markers.

This is passive: it only pattern-matches data already present in the
response that was fetched for the header/TLS checks. It does not send any
additional requests.
"""

from __future__ import annotations

import re

_COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Servlet container)",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel",
    "django_language": "Django",
    "csrftoken": "Django",
    "connect.sid": "Express.js (Node.js)",
    "_rails_session": "Ruby on Rails",
}

_HEADER_SIGNATURES = {
    "x-powered-by": lambda v: v.strip(),
    "x-generator": lambda v: v.strip(),
    "x-drupal-cache": lambda _v: "Drupal",
    "x-aspnet-version": lambda _v: "ASP.NET",
}

_BODY_SIGNATURES = [
    (re.compile(rb'name=["\']generator["\']\s+content=["\']([^"\']+)', re.I), None),
    (re.compile(rb"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(rb"/sites/default/files", re.I), "Drupal"),
    (re.compile(rb"Shopify\.theme", re.I), "Shopify"),
]


def fingerprint(
    headers: list[tuple[str, str]],
    *,
    server_header: str | None = None,
    body: bytes = b"",
) -> list[str]:
    """Return a de-duplicated, best-effort list of technology guesses."""
    findings: set[str] = set()

    if server_header:
        findings.add(f"Server: {server_header.strip()}")

    for name, value in headers:
        handler = _HEADER_SIGNATURES.get(name.lower())
        if handler:
            result = handler(value)
            if result:
                findings.add(result)

    for name, value in headers:
        if name.lower() == "set-cookie":
            cookie_name = value.split("=", 1)[0].strip()
            for prefix, tech in _COOKIE_SIGNATURES.items():
                if cookie_name == prefix or cookie_name.startswith(prefix):
                    findings.add(tech)

    for pattern, tech in _BODY_SIGNATURES:
        match = pattern.search(body)
        if match:
            if tech is None and match.groups():
                findings.add(match.group(1).decode(errors="replace").strip())
            elif tech:
                findings.add(tech)

    return sorted(findings)
