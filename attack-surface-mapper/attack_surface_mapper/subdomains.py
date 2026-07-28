"""Passive subdomain discovery via certificate transparency logs (crt.sh).

Querying crt.sh is a read-only lookup against a public CT log aggregator —
it never contacts the target's own infrastructure, so it needs no
authorization gate (unlike the active scanning stages in this tool).
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .models import Subdomain

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
USER_AGENT = "attack-surface-mapper/0.1 (authorized-recon-tool)"


def fetch_crtsh(domain: str, timeout: float = 10.0) -> list[dict]:
    """Query crt.sh for certificates issued to `domain` or its subdomains.

    Returns an empty list on any network/parse error rather than raising,
    since crt.sh availability shouldn't be a hard dependency for the tool.
    """
    url = CRTSH_URL.format(domain=domain)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return []

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def parse_subdomains(entries: list[dict], domain: str) -> list[str]:
    """Extract a deduplicated, sorted list of hostnames under `domain`.

    crt.sh's `name_value` field can contain multiple newline-separated
    names per certificate (e.g. SANs), and wildcard entries (`*.foo.com`).
    """
    domain = domain.lower().lstrip(".")
    apex_suffix = f".{domain}"
    names: set[str] = set()

    for entry in entries:
        raw_names = entry.get("name_value", "")
        for name in raw_names.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name:
                continue
            if name == domain or name.endswith(apex_suffix):
                names.add(name)

    return sorted(names)


def resolve(
    hostnames: list[str],
    timeout: float = 5.0,
    max_workers: int = 10,
    resolver=socket.gethostbyname,
) -> dict[str, str | None]:
    """Resolve each hostname to an IPv4 address, `None` if resolution fails."""

    def _resolve_one(name: str) -> tuple[str, str | None]:
        socket.setdefaulttimeout(timeout)
        try:
            return name, resolver(name)
        except (socket.gaierror, socket.timeout, OSError):
            return name, None

    if not hostnames:
        return {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = pool.map(_resolve_one, hostnames)

    return dict(results)


def discover(
    domain: str,
    timeout: float = 10.0,
    resolve_dns: bool = True,
    max_workers: int = 10,
    fetcher=fetch_crtsh,
    resolver=socket.gethostbyname,
) -> list[Subdomain]:
    """Full passive-discovery pipeline: crt.sh lookup -> parse -> DNS resolve."""
    entries = fetcher(domain, timeout)
    names = parse_subdomains(entries, domain)

    if not names:
        return []

    if not resolve_dns:
        return [Subdomain(name=name, ip=None) for name in names]

    ip_map = resolve(names, timeout=timeout, max_workers=max_workers, resolver=resolver)
    return [Subdomain(name=name, ip=ip_map.get(name)) for name in names]
