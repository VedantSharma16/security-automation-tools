"""Thin wrappers around actual network I/O (DNS, HTTP, TLS, WHOIS).

Isolated in one module, with no logic of its own, so that
:mod:`recon_agent.tools` can be exercised in tests by monkeypatching these
functions instead of touching the network.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request


def resolve_host(host: str) -> list[str]:
    """Resolve a hostname to a sorted list of unique IP addresses (A/AAAA)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def http_get_headers(host: str, use_https: bool = True, timeout: float = 5.0) -> tuple[int, dict]:
    """Issue a GET request and return ``(status_code, headers_dict)``."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}/"
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "recon-agent/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - deliberate recon probe
        return response.status, dict(response.headers)


def fetch_tls_certificate(host: str, port: int = 443, timeout: float = 5.0) -> tuple[dict, str]:
    """Open a TLS connection and return ``(peer_certificate, negotiated_protocol)``."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            return tls_sock.getpeercert(), tls_sock.version()


def whois_query(domain: str):
    """Return a whois record object, or ``None`` if python-whois isn't installed."""
    try:
        import whois  # type: ignore
    except ImportError:
        return None
    return whois.whois(domain)
