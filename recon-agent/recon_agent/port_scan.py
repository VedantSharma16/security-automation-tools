"""TCP connect-scan with best-effort banner grabbing.

A deliberately simple, non-stealthy connect-scan (`socket.create_connection`)
-- the same technique `port_scanner.py` in the repo root used, but now with
a timeout, concurrency, structured results, and an injectable connector so
it can be unit tested without opening real sockets.
"""

from __future__ import annotations

import concurrent.futures
import socket
from dataclasses import dataclass
from typing import Callable

Connector = Callable[[tuple, float], socket.socket]

COMMON_PORTS: list[int] = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                           1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]


def default_connector(address: tuple, timeout: float) -> socket.socket:
    return socket.create_connection(address, timeout=timeout)


@dataclass(frozen=True)
class PortResult:
    port: int
    open: bool
    banner: str | None

    def to_dict(self) -> dict:
        return {"port": self.port, "open": self.open, "banner": self.banner}


def _probe_port(ip: str, port: int, timeout: float, connector: Connector) -> PortResult:
    try:
        sock = connector((ip, port), timeout)
    except OSError:
        return PortResult(port=port, open=False, banner=None)

    banner = None
    try:
        sock.settimeout(timeout)
        data = sock.recv(256)
        if data:
            banner = data.decode(errors="replace").strip()
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return PortResult(port=port, open=True, banner=banner)


def scan_ports(
    ip: str,
    ports: list[int] = COMMON_PORTS,
    timeout: float = 1.0,
    connector: Connector = default_connector,
    max_workers: int = 20,
) -> list[PortResult]:
    """Connect-scan `ports` on `ip`, returning only the ones found open.

    Runs probes concurrently via a thread pool since each probe is I/O-bound
    and dominated by the connect timeout.
    """
    results: list[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_port, ip, port, timeout, connector): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.open:
                results.append(result)
    return sorted(results, key=lambda r: r.port)
