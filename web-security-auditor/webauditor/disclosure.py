"""Information-disclosure checks: sensitive path probing and robots.txt review."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin

import yaml

from .fetch import Fetcher
from .findings import Finding, Severity

DEFAULT_SENSITIVE_PATHS = Path(__file__).resolve().parent.parent / "rules" / "sensitive_paths.yaml"

_INTERESTING_ROBOTS_MARKERS = (
    "admin",
    "backup",
    "config",
    "private",
    ".git",
    ".env",
    "secret",
    "internal",
)


def load_sensitive_paths(path: Path = DEFAULT_SENSITIVE_PATHS) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or []
    return data


def check_sensitive_paths(fetcher: Fetcher, base_url: str, path_specs: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for spec in path_specs:
        result = fetcher.get(urljoin(base_url, spec["path"]))
        if not result.ok or result.status_code != 200 or not result.body.strip():
            continue

        evidence = result.body.strip().replace("\n", " ")[:160]
        findings.append(
            Finding(
                id=spec["id"],
                title=("Informational: " if spec.get("positive") else "Exposed path: ")
                + spec["path"],
                severity=Severity(_severity_value(spec["severity"])),
                owasp_category="A05:2021 Security Misconfiguration",
                description=spec["description"],
                evidence=f"GET {spec['path']} -> 200; {evidence}",
                remediation="Remove or restrict access to this path."
                if not spec.get("positive")
                else "",
            )
        )
    return findings


def check_robots_txt(fetcher: Fetcher, base_url: str) -> list[Finding]:
    result = fetcher.get(urljoin(base_url, "/robots.txt"))
    if not result.ok or result.status_code != 200:
        return []

    interesting: list[str] = []
    for line in result.body.splitlines():
        line = line.strip()
        if not line.lower().startswith("disallow:"):
            continue
        entry = line.split(":", 1)[1].strip()
        if entry and any(marker in entry.lower() for marker in _INTERESTING_ROBOTS_MARKERS):
            interesting.append(entry)

    if not interesting:
        return []

    return [
        Finding(
            id="robots-txt-interesting-disallow",
            title="robots.txt discloses potentially sensitive paths",
            severity=Severity.INFO,
            owasp_category="A05:2021 Security Misconfiguration",
            description="robots.txt lists Disallow entries that look like "
            "internal/admin paths. This is not a vulnerability by itself — "
            "robots.txt is advisory, not access control — but it's useful "
            "reconnaissance for narrowing where else to look.",
            evidence=", ".join(interesting[:10]),
            remediation="Enforce access control server-side; don't rely on "
            "robots.txt to hide paths.",
        )
    ]


def _severity_value(name: str) -> int:
    return Severity[name.upper()].value
