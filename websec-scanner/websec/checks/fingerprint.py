"""Passive technology fingerprinting from headers and HTML markers."""

from __future__ import annotations

import re

from ..models import Finding, Severity

CHECK_NAME = "fingerprint"

_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE
)

# Body-content markers -> technology name, for cases with no generator tag.
_CONTENT_SIGNATURES = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "/sites/default/files": "Drupal",
    "Joomla!": "Joomla",
    "csrfmiddlewaretoken": "Django",
    "__VIEWSTATE": "ASP.NET WebForms",
}


def fingerprint(url: str, headers: dict, body: str) -> list[Finding]:
    """Report detected technologies as informational findings (not a
    vulnerability by itself, but useful recon context for a pentester).
    """
    detected: set[str] = set()

    server = headers.get("Server", "")
    if server:
        detected.add(server)

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        detected.add(powered_by)

    match = _GENERATOR_RE.search(body)
    if match:
        detected.add(match.group(1))

    for marker, tech in _CONTENT_SIGNATURES.items():
        if marker in body:
            detected.add(tech)

    if not detected:
        return []

    return [
        Finding(
            check=CHECK_NAME,
            severity=Severity.INFO,
            title="Technology stack fingerprinted",
            url=url,
            detail="Detected: " + ", ".join(sorted(detected)),
            evidence=", ".join(sorted(detected)),
            recommendation="Informational only -- use to prioritize which "
            "CVEs/known misconfigurations to check for this stack.",
        )
    ]
