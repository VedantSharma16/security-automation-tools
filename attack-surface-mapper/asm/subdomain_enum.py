"""Passive subdomain discovery via certificate transparency logs (crt.sh).

This is a purely passive technique: it never touches the target directly.
It works by querying crt.sh's public database of every TLS certificate that
has ever been issued for the domain (or a subdomain of it) and pulling
subdomain names out of the certificates' Subject Alternative Names. It's a
standard first step in real recon (subfinder, amass, and OWASP Amass all
use the same trick), and it commonly surfaces forgotten staging/dev/admin
hosts that were never meant to be public.
"""

from __future__ import annotations

import requests

from .findings import Finding, Severity

CRTSH_URL = "https://crt.sh/"
LARGE_SURFACE_THRESHOLD = 50


class SubdomainEnumError(Exception):
    """Raised when the crt.sh query fails (network error, bad response, etc.)."""


def query_crtsh(
    domain: str, timeout: float = 15.0, session: requests.Session | None = None
) -> list[str]:
    """Return the sorted, deduplicated set of subdomains found for `domain`."""
    session = session or requests.Session()
    try:
        response = session.get(
            CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout
        )
        response.raise_for_status()
        entries = response.json()
    except requests.RequestException as exc:
        raise SubdomainEnumError(f"crt.sh query failed: {exc}") from exc
    except ValueError as exc:
        raise SubdomainEnumError(f"crt.sh returned an unparseable response: {exc}") from exc

    names: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name and not name.startswith("*."):
                names.add(name)

    return sorted(names)


def build_findings(domain: str, subdomains: list[str]) -> list[Finding]:
    findings = [
        Finding(
            source="subdomains",
            severity=Severity.INFO,
            title=f"{len(subdomains)} subdomain(s) discovered via certificate transparency",
            detail=", ".join(subdomains) if subdomains else "none found",
        )
    ]
    if len(subdomains) > LARGE_SURFACE_THRESHOLD:
        findings.append(
            Finding(
                source="subdomains",
                severity=Severity.LOW,
                title="Large discoverable attack surface",
                detail=(
                    f"{len(subdomains)} distinct hostnames were found for {domain}, "
                    "which is more exposed surface to inventory and patch than a "
                    "typical deployment. Confirm every host is still in active use."
                ),
            )
        )
    return findings
