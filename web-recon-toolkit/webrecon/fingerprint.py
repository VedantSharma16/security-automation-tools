"""Lightweight, informational technology fingerprinting from headers/body/cookies.

Not a vulnerability check by itself (findings are INFO severity) — this is
recon context: knowing the stack narrows which CVEs and default-credential
lists are worth trying next.
"""

from __future__ import annotations

import re
from typing import Mapping

from .models import Finding, Severity

_COOKIE_TECH = {
    "phpsessid": "PHP",
    "jsessionid": "Java (JSP/Servlet)",
    "asp.net_sessionid": "ASP.NET",
    "csrftoken": "Django",
    "sessionid": "Django",
    "laravel_session": "Laravel (PHP)",
    "connect.sid": "Node.js (Express)",
}

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE
)


def fingerprint(
    headers: Mapping[str, str], body: str = "", cookie_names: list[str] | None = None
) -> list[Finding]:
    """Return INFO-severity Findings summarizing detected server/framework tech."""
    findings: list[Finding] = []
    detected: set[str] = set()

    for header in ("Server", "X-Powered-By"):
        value = headers.get(header)
        if value:
            detected.add(f"{header}: {value}")

    match = _GENERATOR_RE.search(body)
    if match:
        detected.add(f"generator meta tag: {match.group(1)}")

    for name in cookie_names or []:
        tech = _COOKIE_TECH.get(name.lower())
        if tech:
            detected.add(f"cookie '{name}' suggests {tech}")

    if detected:
        findings.append(
            Finding(
                id="fingerprint-tech-stack",
                title="Technology stack fingerprinted",
                severity=Severity.INFO,
                category="fingerprint",
                description=(
                    "The following signals were observed and can help focus "
                    "further manual testing (known CVEs, default configs, "
                    "framework-specific attack surface): " + "; ".join(sorted(detected))
                ),
                evidence="; ".join(sorted(detected)),
                remediation=(
                    "None required by itself; consider suppressing version strings "
                    "in `Server`/`X-Powered-By` to reduce fingerprinting surface."
                ),
                owasp_ref="A05:2021-Security Misconfiguration",
            )
        )
    return findings
