"""robots.txt / sitemap.xml recon: both are self-disclosed maps of paths the site owner cares about."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from .fetcher import fetch
from .models import Finding, Severity

INTERESTING_KEYWORDS = [
    "admin", "backup", "config", "wp-admin", ".git", ".env", "private",
    "internal", "staging", "dev", "test", "api", "db", "sql", "secret",
    "credentials", "debug",
]

_LOC_PATTERN = re.compile(r"<loc>(.*?)</loc>", re.IGNORECASE | re.DOTALL)


def parse_robots(body: str) -> list[str]:
    """Extract Disallow/Allow path values from a robots.txt body, skipping wildcards ('/')."""
    paths = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() in ("disallow", "allow"):
            value = value.strip()
            if value and value != "/":
                paths.append(value)
    return paths


def _scan_robots(base_url: str, fetch_fn) -> list[Finding]:
    result = fetch_fn(urljoin(base_url, "/robots.txt"))
    if not result.ok or result.status != 200:
        return []

    paths = parse_robots(result.body)
    if not paths:
        return []

    findings = [
        Finding(
            id="robots-txt-present",
            title=f"robots.txt discloses {len(paths)} path(s)",
            severity=Severity.INFO,
            detail=(
                f"robots.txt lists {len(paths)} disallowed/allowed path(s) — a self-disclosed "
                "map of areas the site owner doesn't want crawled, often useful recon context."
            ),
            category="robots",
        )
    ]

    interesting = [p for p in paths if any(k in p.lower() for k in INTERESTING_KEYWORDS)]
    if interesting:
        sample = ", ".join(interesting[:8])
        more = f" (+{len(interesting) - 8} more)" if len(interesting) > 8 else ""
        findings.append(
            Finding(
                id="robots-txt-sensitive-paths",
                title="robots.txt references sensitive-looking paths",
                severity=Severity.LOW,
                detail=f"Paths worth manually reviewing: {sample}{more}.",
                category="robots",
                recommendation="robots.txt is not access control — confirm these paths also require authentication.",
            )
        )
    return findings


def _scan_sitemap(base_url: str, fetch_fn) -> list[Finding]:
    result = fetch_fn(urljoin(base_url, "/sitemap.xml"))
    if not result.ok or result.status != 200:
        return []

    urls = _LOC_PATTERN.findall(result.body)
    if not urls:
        return []

    return [
        Finding(
            id="sitemap-xml-present",
            title=f"sitemap.xml lists {len(urls)} URL(s)",
            severity=Severity.INFO,
            detail="sitemap.xml is reachable and enumerates site URLs, useful for building a content/endpoint map quickly.",
            category="robots",
        )
    ]


def scan(base_url: str, fetch_fn=fetch) -> list[Finding]:
    """Check robots.txt and sitemap.xml for disclosed paths and interesting content."""
    return _scan_robots(base_url, fetch_fn) + _scan_sitemap(base_url, fetch_fn)
