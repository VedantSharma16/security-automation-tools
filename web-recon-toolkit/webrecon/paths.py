"""Discover accidentally-exposed sensitive files and paths on a target web app.

Uses a small, conservative built-in wordlist by default (source-control
metadata, secret files, backups, common admin/debug endpoints). A soft-404
baseline request is made first so hosts that return HTTP 200 for every path
(SPA catch-alls, custom error pages) don't produce false positives.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Callable

from .models import Finding, Severity

# (path, title, severity, category, description)
DEFAULT_SENSITIVE_PATHS: list[tuple[str, str, Severity, str]] = [
    (".git/config", "Exposed .git/config", Severity.CRITICAL, "vcs disclosure"),
    (".git/HEAD", "Exposed .git/HEAD", Severity.CRITICAL, "vcs disclosure"),
    (".svn/entries", "Exposed .svn/entries", Severity.CRITICAL, "vcs disclosure"),
    (".env", "Exposed .env file", Severity.CRITICAL, "secrets disclosure"),
    (".env.local", "Exposed .env.local file", Severity.CRITICAL, "secrets disclosure"),
    (".aws/credentials", "Exposed AWS credentials file", Severity.CRITICAL, "secrets disclosure"),
    ("id_rsa", "Exposed private SSH key", Severity.CRITICAL, "secrets disclosure"),
    ("config.php.bak", "Exposed config backup file", Severity.HIGH, "secrets disclosure"),
    ("wp-config.php.bak", "Exposed WordPress config backup", Severity.HIGH, "secrets disclosure"),
    ("web.config", "Exposed IIS web.config", Severity.HIGH, "config disclosure"),
    (".htpasswd", "Exposed .htpasswd file", Severity.HIGH, "secrets disclosure"),
    ("backup.zip", "Exposed backup archive", Severity.HIGH, "backup disclosure"),
    ("backup.sql", "Exposed database backup", Severity.HIGH, "backup disclosure"),
    ("database.sql", "Exposed database dump", Severity.HIGH, "backup disclosure"),
    ("dump.sql", "Exposed database dump", Severity.HIGH, "backup disclosure"),
    ("docker-compose.yml", "Exposed docker-compose.yml", Severity.MEDIUM, "config disclosure"),
    ("phpinfo.php", "Exposed phpinfo() page", Severity.MEDIUM, "info disclosure"),
    ("server-status", "Exposed Apache mod_status page", Severity.MEDIUM, "info disclosure"),
    ("actuator/env", "Exposed Spring Boot actuator env endpoint", Severity.HIGH, "info disclosure"),
    (".DS_Store", "Exposed .DS_Store file", Severity.LOW, "info disclosure"),
    ("admin/", "Unauthenticated admin path reachable", Severity.INFO, "exposed endpoint"),
]

_PROBE_TIMEOUT_DEFAULT = 5.0


@dataclass
class _Baseline:
    status_code: int
    length: int


def discover_sensitive_paths(
    base_url: str,
    get: Callable[[str, float], tuple[int, bytes]],
    paths: list[tuple[str, str, Severity, str]] | None = None,
    delay: float = 0.0,
    timeout: float = _PROBE_TIMEOUT_DEFAULT,
) -> list[Finding]:
    """Probe `paths` under `base_url` and return a Finding for each real hit.

    `get(url, timeout) -> (status_code, body_bytes)` is injected so tests
    (and callers) control the HTTP layer without depending on `requests`
    directly here.
    """
    base_url = base_url.rstrip("/")
    paths = paths if paths is not None else DEFAULT_SENSITIVE_PATHS

    baseline = _probe_baseline(base_url, get, timeout)

    findings: list[Finding] = []
    for path, title, severity, category in paths:
        if delay:
            time.sleep(delay)
        url = f"{base_url}/{path}"
        try:
            status, body = get(url, timeout)
        except Exception:  # noqa: BLE001 - network errors are non-findings, not crashes
            continue

        if not _is_real_hit(status, body, baseline):
            continue

        findings.append(
            Finding(
                id=f"path-{path.strip('/').replace('/', '-')}",
                title=title,
                severity=severity,
                category=category,
                description=(
                    f"GET {url} returned HTTP {status} with a body distinct from "
                    "the site's not-found baseline, indicating the resource is "
                    "actually served."
                ),
                evidence=f"HTTP {status}, {len(body)} bytes",
                remediation=(
                    "Remove the file from the deployed web root, block it at the "
                    "reverse proxy, or restrict it with authentication."
                ),
                owasp_ref="A05:2021-Security Misconfiguration",
            )
        )
    return findings


def _probe_baseline(
    base_url: str, get: Callable[[str, float], tuple[int, bytes]], timeout: float
) -> _Baseline:
    nonce_path = f"{base_url}/__webrecon_nonexistent_{uuid.uuid4().hex}__"
    try:
        status, body = get(nonce_path, timeout)
        return _Baseline(status_code=status, length=len(body))
    except Exception:  # noqa: BLE001
        return _Baseline(status_code=404, length=0)


def _is_real_hit(status: int, body: bytes, baseline: _Baseline) -> bool:
    if status >= 400:
        return False
    if status != baseline.status_code:
        return True
    # Same status as the soft-404 baseline (e.g. both 200 on an SPA):
    # only count it if the body is meaningfully different in size.
    if baseline.length == 0:
        return len(body) > 0
    size_delta = abs(len(body) - baseline.length) / max(baseline.length, 1)
    return size_delta > 0.10
