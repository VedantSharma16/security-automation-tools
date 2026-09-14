"""Optional check for commonly-exposed sensitive paths.

Disabled by default and only run when the caller opts in (``--check-exposed``
on the CLI), since it issues extra requests beyond the initial page fetch.
Only ever requests paths on the same host that was already targeted —
never used to discover or scan unrelated hosts. Use only against systems
you are authorized to test.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from http_audit.fetcher import HttpResponse
from http_audit.report import Finding

SENSITIVE_PATHS: dict[str, str] = {
    "/.git/HEAD": "Exposed .git directory can leak full source history.",
    "/.env": "Exposed .env file commonly contains credentials/API keys.",
    "/.aws/credentials": "Exposed AWS credentials file would grant cloud account access.",
    "/wp-config.php.bak": "Backup of WordPress config commonly contains DB credentials.",
    "/.well-known/security.txt": "Informational: presence indicates a documented vulnerability disclosure contact.",
}

Transport = Callable[[str], HttpResponse]


def check_exposure(base_url: str, transport: Transport) -> list[Finding]:
    parts = urlsplit(base_url)
    findings: list[Finding] = []

    for path, description in SENSITIVE_PATHS.items():
        target = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
        try:
            response = transport(target)
        except Exception:
            continue

        found = response.status == 200
        is_informational = path == "/.well-known/security.txt"

        if found and is_informational:
            findings.append(Finding("exposure", path, "info", description))
        elif found:
            findings.append(
                Finding(
                    "exposure",
                    path,
                    "critical",
                    f"{path} returned HTTP 200. {description}",
                    "Remove public access to this path (web server config, .htaccess, or deployment exclude rules).",
                )
            )

    return findings
