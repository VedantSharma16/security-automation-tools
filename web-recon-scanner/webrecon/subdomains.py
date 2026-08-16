"""DNS brute-force subdomain enumeration.

Resolution is done through an injectable `resolver` callable (defaulting to
`socket.gethostbyname`) so the concurrency/aggregation logic can be unit
tested without touching real DNS.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

DEFAULT_WORDLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "subdomain_wordlist.txt"


@dataclass(frozen=True)
class SubdomainResult:
    subdomain: str
    resolved: bool
    address: str | None


def load_wordlist(path: Path = DEFAULT_WORDLIST_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _resolve_one(fqdn: str, resolver) -> SubdomainResult:
    try:
        address = resolver(fqdn)
        return SubdomainResult(subdomain=fqdn, resolved=True, address=address)
    except (socket.gaierror, OSError):
        return SubdomainResult(subdomain=fqdn, resolved=False, address=None)


def enumerate_subdomains(domain: str, wordlist: list, resolver=socket.gethostbyname, max_workers: int = 20) -> list:
    """Resolve `<word>.<domain>` for every word in `wordlist`, concurrently.

    Returns only the subdomains that resolved, sorted alphabetically.
    """
    candidates = [f"{word}.{domain}" for word in wordlist]
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_resolve_one, fqdn, resolver) for fqdn in candidates]
        for future in as_completed(futures):
            results.append(future.result())

    resolved = [r for r in results if r.resolved]
    resolved.sort(key=lambda r: r.subdomain)
    return resolved
