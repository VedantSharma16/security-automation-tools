"""Threaded TCP connect-scan of a small, curated port list.

This is an *active* technique — it opens real connections to the target
host. The CLI gates this stage behind an explicit authorization flag
(see `cli.py`); this module itself has no such gate since it may also be
useful embedded in other authorized tooling.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .models import OpenPort

# A deliberately small, common-service port list rather than a full
# 1-65535 sweep — this is a recon aid, not a substitute for a dedicated
# scanner like nmap, and a smaller list is faster and less disruptive.
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}

# Ports that are rarely meant to be internet-facing; finding these open on
# an external host is a stronger signal than, say, 80/443 being open.
SENSITIVE_PORTS: frozenset[int] = frozenset(
    {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
)


def scan_port(
    host: str, port: int, timeout: float = 1.0, connector=socket.create_connection
) -> bool:
    """Return True if a TCP connection to (host, port) succeeds."""
    try:
        with connector((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_host(
    host: str,
    ports: dict[int, str] | None = None,
    timeout: float = 1.0,
    max_workers: int = 20,
    connector=socket.create_connection,
) -> list[OpenPort]:
    """Scan `host` across `ports` (default: COMMON_PORTS), threaded."""
    ports = COMMON_PORTS if ports is None else ports

    def _check(item: tuple[int, str]) -> OpenPort | None:
        port, service = item
        if scan_port(host, port, timeout=timeout, connector=connector):
            return OpenPort(port=port, service=service, sensitive=port in SENSITIVE_PORTS)
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(pool.map(_check, ports.items()))

    open_ports = [r for r in results if r is not None]
    return sorted(open_ports, key=lambda p: p.port)
