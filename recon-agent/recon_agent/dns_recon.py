"""DNS resolution and subdomain enumeration.

Uses only the standard library (`socket.gethostbyname`) so the tool has no
required third-party dependencies. Every network call is exposed as an
injectable parameter so the whole module is testable without touching a
real network or DNS server.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Callable

Resolver = Callable[[str], str]


def default_resolver(hostname: str) -> str:
    return socket.gethostbyname(hostname)


@dataclass(frozen=True)
class DnsResult:
    hostname: str
    resolved: bool
    ip: str | None
    error: str | None

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "resolved": self.resolved,
            "ip": self.ip,
            "error": self.error,
        }


def resolve_host(hostname: str, resolver: Resolver = default_resolver) -> DnsResult:
    """Resolve `hostname` to an IPv4 address, capturing failure instead of raising."""
    try:
        ip = resolver(hostname)
        return DnsResult(hostname=hostname, resolved=True, ip=ip, error=None)
    except OSError as exc:
        return DnsResult(hostname=hostname, resolved=False, ip=None, error=str(exc))


@dataclass(frozen=True)
class SubdomainResult:
    subdomain: str
    ip: str

    def to_dict(self) -> dict:
        return {"subdomain": self.subdomain, "ip": self.ip}


def load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def enumerate_subdomains(
    domain: str,
    words: list[str],
    resolver: Resolver = default_resolver,
    limit: int | None = None,
) -> list[SubdomainResult]:
    """Brute-force common subdomain labels against `domain` and keep the ones that resolve.

    This is passive from the target's perspective in the sense that it only
    issues standard DNS queries (the same as any browser would) - no
    exploitation, no traffic to the host itself.
    """
    candidates = words if limit is None else words[:limit]
    found: list[SubdomainResult] = []
    for word in candidates:
        fqdn = f"{word}.{domain}"
        try:
            ip = resolver(fqdn)
        except OSError:
            continue
        found.append(SubdomainResult(subdomain=fqdn, ip=ip))
    return found
