"""Passive checks for common accidentally-exposed paths.

Every check is a single GET request to a well-known path - the same class
of request a browser or crawler would make. There is no brute forcing,
credential guessing, or payload injection here, only a fixed, small list
of known-sensitive locations.
"""

from __future__ import annotations

from typing import Callable

from .findings import Finding, Severity
from .fetcher import FetchResult

# (path, id, title, severity, description, recommendation)
_SENSITIVE_PATHS = [
    (".git/HEAD", "EXP-GIT-EXPOSED", "Exposed .git directory", Severity.CRITICAL,
     "The .git directory is web-accessible, which can allow an attacker to "
     "reconstruct source code, commit history, and any secrets ever committed.",
     "Block web access to .git/ (e.g. deny in the web server config) or "
     "remove it from the deployed document root entirely."),
    (".env", "EXP-DOTENV-EXPOSED", "Exposed .env file", Severity.CRITICAL,
     "A .env file is web-accessible. These files commonly contain database "
     "credentials, API keys, and other secrets.",
     "Remove .env from the web root and ensure the web server denies "
     "dotfiles."),
    (".svn/entries", "EXP-SVN-EXPOSED", "Exposed .svn directory", Severity.HIGH,
     "The .svn metadata directory is web-accessible, exposing source and "
     "version history.",
     "Block web access to .svn/ or remove it from the deployed directory."),
    ("server-status", "EXP-APACHE-SERVER-STATUS", "Apache mod_status exposed", Severity.HIGH,
     "Apache's server-status page is publicly accessible, leaking active "
     "requests, client IPs, and internal URLs.",
     "Restrict server-status to localhost/internal networks only."),
    ("wp-config.php.bak", "EXP-WP-CONFIG-BACKUP", "Exposed WordPress config backup", Severity.CRITICAL,
     "A backup of wp-config.php is web-accessible and likely contains "
     "database credentials and secret keys.",
     "Delete backup files from the web root; never leave editor/backup "
     "artifacts (.bak, ~, .swp) in a served directory."),
    (".DS_Store", "EXP-DS-STORE", "Exposed .DS_Store file", Severity.LOW,
     "A macOS .DS_Store file is web-accessible and can reveal the names of "
     "other files/directories on the server.",
     "Remove .DS_Store files from deployments and exclude them in the "
     "build/deploy pipeline."),
]

# Informational, non-vulnerability checks reported separately from risk findings.
_INFO_PATHS = [
    ("robots.txt", "EXP-ROBOTS-TXT", "robots.txt present",
     "robots.txt can reveal paths the site owner considers sensitive "
     "enough to hide from search engines, which may still be interesting "
     "to an attacker."),
    (".well-known/security.txt", "EXP-SECURITY-TXT", "security.txt present",
     "RFC 9116 security.txt found - the site publishes a responsible "
     "disclosure contact. This is a positive signal, not a vulnerability."),
]

FetchFn = Callable[[str], FetchResult]


def _looks_present(result: FetchResult) -> bool:
    return result.ok and result.status_code == 200 and len(result.body_preview.strip()) > 0


def check_exposed_paths(base_url: str, fetch_fn: FetchFn) -> list[Finding]:
    """Probe a fixed list of known-sensitive paths under base_url.

    fetch_fn takes a full URL and returns a FetchResult - injected so tests
    never perform real network I/O.
    """
    findings: list[Finding] = []
    base = base_url.rstrip("/")

    for path, finding_id, title, severity, description, recommendation in _SENSITIVE_PATHS:
        result = fetch_fn(f"{base}/{path}")
        if _looks_present(result):
            findings.append(Finding(
                id=finding_id,
                title=title,
                severity=severity,
                category="exposure",
                description=description,
                recommendation=recommendation,
                evidence=f"GET {base}/{path} -> HTTP {result.status_code}",
            ))

    for path, finding_id, title, description in _INFO_PATHS:
        result = fetch_fn(f"{base}/{path}")
        if _looks_present(result):
            findings.append(Finding(
                id=finding_id,
                title=title,
                severity=Severity.INFO,
                category="exposure",
                description=description,
                recommendation="No action required.",
                evidence=f"GET {base}/{path} -> HTTP {result.status_code}",
            ))

    return findings
