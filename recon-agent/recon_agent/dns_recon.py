"""DNS resolution and wordlist-based subdomain enumeration."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Callable

Resolver = Callable[[str], str | None]


def resolve(host: str) -> str | None:
    """Resolve a hostname to an IPv4 address, or None if it doesn't resolve."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def enumerate_subdomains(
    domain: str,
    wordlist: list[str],
    *,
    max_workers: int = 20,
    resolver: Resolver | None = None,
) -> dict[str, str]:
    """Resolve ``{word}.{domain}`` for each word in ``wordlist`` concurrently.

    Returns a mapping of the subdomains that resolved to their IP address.
    ``resolver`` is injectable so callers (and tests) can avoid real DNS.
    """
    resolver = resolver or resolve
    found: dict[str, str] = {}
    if not wordlist:
        return found

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        candidates = {f"{word}.{domain}": word for word in wordlist}
        futures = {pool.submit(resolver, host): host for host in candidates}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            ip = future.result()
            if ip:
                found[host] = ip
    return found
