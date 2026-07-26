"""Probes for commonly-exposed sensitive files and paths.

Every probe is a plain GET/HEAD against a path relative to the scan target
-- no destructive methods, no write operations.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Finding, Severity

CHECK_NAME = "exposure"


@dataclass(frozen=True)
class ExposureProbe:
    path: str
    severity: Severity
    title: str
    recommendation: str
    # Optional substring(s) that must appear in the body for a 200 to count
    # as a real hit (cuts down false positives from custom 200 error pages).
    content_markers: tuple = ()


PROBES: tuple = (
    ExposureProbe(
        path=".git/config",
        severity=Severity.CRITICAL,
        title="Exposed .git directory",
        content_markers=("[core]",),
        recommendation="Remove the .git directory from the deployed web root "
        "(or block it at the web server) -- it can leak full source history.",
    ),
    ExposureProbe(
        path=".git/HEAD",
        severity=Severity.CRITICAL,
        title="Exposed .git directory",
        content_markers=("ref:",),
        recommendation="Remove the .git directory from the deployed web root "
        "(or block it at the web server) -- it can leak full source history.",
    ),
    ExposureProbe(
        path=".env",
        severity=Severity.CRITICAL,
        title="Exposed .env file",
        content_markers=(),
        recommendation="Never deploy .env files into the web root; load "
        "secrets from environment variables or a secrets manager instead.",
    ),
    ExposureProbe(
        path=".svn/entries",
        severity=Severity.HIGH,
        title="Exposed .svn directory",
        content_markers=(),
        recommendation="Remove .svn metadata from the deployed web root.",
    ),
    ExposureProbe(
        path="wp-config.php.bak",
        severity=Severity.CRITICAL,
        title="Exposed backup of wp-config.php",
        content_markers=(),
        recommendation="Delete editor/deploy backup files (*.bak, *.old, *~) "
        "from the web root; they often bypass PHP execution and are served "
        "as plaintext.",
    ),
    ExposureProbe(
        path="id_rsa",
        severity=Severity.CRITICAL,
        title="Exposed private key file",
        content_markers=("PRIVATE KEY",),
        recommendation="Remove private key material from the web root "
        "immediately and rotate the key.",
    ),
    ExposureProbe(
        path="server-status",
        severity=Severity.MEDIUM,
        title="Exposed Apache server-status page",
        content_markers=("Apache Server Status",),
        recommendation="Restrict mod_status to localhost/internal networks only.",
    ),
    ExposureProbe(
        path="phpinfo.php",
        severity=Severity.HIGH,
        title="Exposed phpinfo() page",
        content_markers=("phpinfo()",),
        recommendation="Remove phpinfo() debug pages before deploying to "
        "production -- they disclose detailed environment and path info.",
    ),
)

# Informational-only: presence is not itself a finding, but disclosed paths
# are surfaced so an operator/pentester can follow up manually.
ROBOTS_PATH = "robots.txt"


def evaluate_probe_response(probe: ExposureProbe, status_code: int, body: str, url: str) -> Finding | None:
    if status_code != 200:
        return None
    if probe.content_markers and not any(marker in body for marker in probe.content_markers):
        return None
    return Finding(
        check=CHECK_NAME,
        severity=probe.severity,
        title=probe.title,
        url=url,
        detail=f"GET {probe.path} returned HTTP 200 with content matching a "
        f"known-sensitive file signature.",
        evidence=body[:200],
        recommendation=probe.recommendation,
    )


def parse_robots_disclosures(body: str) -> list[str]:
    """Pull Disallow/Allow paths out of a robots.txt body.

    These aren't vulnerabilities by themselves, but disallowed paths are a
    classic hint of what an operator considers sensitive enough to hide from
    crawlers -- worth a manual look during recon.
    """
    paths = []
    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith(("disallow:", "allow:")):
            _, _, value = line.partition(":")
            value = value.strip()
            if value and value != "/":
                paths.append(value)
    return paths
