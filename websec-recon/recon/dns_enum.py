"""Passive-ish subdomain enumeration via DNS resolution.

This does not brute-force or query any third-party service by default —
it just resolves `<word>.<domain>` for a small bundled wordlist using
standard DNS lookups, which is the same thing a browser does when you type
a URL. No traffic ever reaches the target host itself from this module.
"""

from __future__ import annotations

import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "subdomain_wordlist.txt"

# Subdomains that, if present, are worth flagging even though DNS resolution
# alone doesn't tell us anything is actually misconfigured — they just
# indicate a broader attack surface (non-production or admin-facing hosts).
_NOTEWORTHY_LABELS = {
    "admin", "dev", "staging", "stage", "test", "uat", "internal",
    "intranet", "vpn", "backup", "old", "beta", "db", "database",
    "jenkins", "gitlab", "kibana", "grafana",
}

Resolver = "callable(str) -> str | None"


@dataclass(frozen=True)
class ResolvedHost:
    hostname: str
    ip: str


def load_wordlist(path: Path | None = None) -> list[str]:
    path = path or DEFAULT_WORDLIST
    words = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    return words


def _default_resolver(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, UnicodeError):
        return None


def enumerate_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    resolver=_default_resolver,
    max_workers: int = 20,
) -> list[ResolvedHost]:
    """Resolve `<word>.<domain>` for every word in `wordlist` concurrently."""
    words = wordlist if wordlist is not None else load_wordlist()
    candidates = [f"{word}.{domain}" for word in words]

    resolved: list[ResolvedHost] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_host = {pool.submit(resolver, host): host for host in candidates}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            ip = future.result()
            if ip:
                resolved.append(ResolvedHost(hostname=host, ip=ip))

    return sorted(resolved, key=lambda h: h.hostname)


def analyze_subdomains(domain: str, resolved: list[ResolvedHost]) -> list[Finding]:
    findings: list[Finding] = []

    if not resolved:
        return findings

    findings.append(
        Finding(
            category="dns",
            title=f"{len(resolved)} subdomain(s) discovered",
            severity="info",
            description=(
                f"DNS resolution succeeded for {len(resolved)} host(s) under "
                f"{domain} from the bundled wordlist."
            ),
            recommendation="Confirm every resolved host is intended to be public.",
            evidence={"hosts": [h.hostname for h in resolved]},
        )
    )

    noteworthy = [
        h for h in resolved if h.hostname.split(".")[0].lower() in _NOTEWORTHY_LABELS
    ]
    if noteworthy:
        findings.append(
            Finding(
                category="dns",
                title="Non-production or admin-facing subdomains exposed",
                severity="medium",
                description=(
                    "Subdomains commonly used for internal, admin, or "
                    "non-production services resolve publicly: "
                    + ", ".join(h.hostname for h in noteworthy)
                ),
                recommendation=(
                    "Restrict these hosts to a VPN/allowlist, or confirm they are "
                    "intentionally public and hardened to the same standard as production."
                ),
                evidence={"hosts": [h.hostname for h in noteworthy]},
            )
        )

    ip_counts = Counter(h.ip for h in resolved)
    dominant_ip, dominant_count = ip_counts.most_common(1)[0]
    if len(resolved) >= 5 and dominant_count == len(resolved):
        findings.append(
            Finding(
                category="dns",
                title="Possible wildcard DNS record",
                severity="low",
                description=(
                    f"All {len(resolved)} resolved subdomains point to the same IP "
                    f"({dominant_ip}), which is consistent with a wildcard DNS record "
                    "rather than distinct hosts."
                ),
                recommendation=(
                    "Verify with a random, unregistered subdomain; if that also "
                    "resolves, subdomain enumeration results here are not reliable."
                ),
                evidence={"ip": dominant_ip},
            )
        )

    return findings
