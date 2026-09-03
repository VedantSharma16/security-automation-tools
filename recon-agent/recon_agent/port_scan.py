"""Threaded TCP connect-scan of a curated, commonly-interesting port set."""

from __future__ import annotations

import concurrent.futures
import socket
from dataclasses import dataclass
from typing import Callable

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "microsoft-ds", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str


Checker = Callable[[str, int, float], PortResult]


def _check(host: str, port: int, timeout: float) -> PortResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return PortResult(port=port, open=(result == 0), service=SERVICE_NAMES.get(port, "unknown"))
    finally:
        sock.close()


def scan_ports(
    host: str,
    *,
    ports: list[int] | None = None,
    timeout: float = 0.75,
    max_workers: int = 50,
    checker: Checker | None = None,
) -> list[PortResult]:
    """Scan ``host`` across ``ports`` and return only the open ones, sorted by port."""
    ports = ports if ports is not None else DEFAULT_PORTS
    checker = checker or _check
    results: list[PortResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(checker, host, port, timeout) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.open:
                results.append(result)

    return sorted(results, key=lambda r: r.port)
