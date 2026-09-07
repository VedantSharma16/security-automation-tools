"""Async TCP connect-scan with lightweight banner grabbing.

Uses asyncio directly instead of a raw-socket/thread-per-port scan so a few
hundred ports can be probed concurrently under one event loop. The connection
factory is injectable (`connect_fn`) purely so tests can exercise the
concurrency/timeout/banner-parsing logic with a fake, in-memory socket
instead of touching the network.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

# Ports where a server typically waits for a request instead of greeting
# first; for these we send a benign HEAD probe if nothing arrives unprompted.
HTTP_PROBE_PORTS = {80, 8000, 8080, 8888}


@dataclass(frozen=True)
class PortResult:
    port: int
    open: bool
    banner: str = ""


async def _probe(host: str, port: int, timeout: float, connect_fn) -> PortResult:
    try:
        reader, writer = await asyncio.wait_for(connect_fn(host, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return PortResult(port=port, open=False)

    banner = ""
    read_timeout = min(timeout, 0.75)
    try:
        data = await asyncio.wait_for(reader.read(512), timeout=read_timeout)
        if not data and port in HTTP_PROBE_PORTS:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            drain = getattr(writer, "drain", None)
            if drain is not None:
                await drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=read_timeout)
        banner = data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        close = getattr(writer, "close", None)
        if close is not None:
            close()

    return PortResult(port=port, open=True, banner=banner)


async def scan_ports_async(
    host: str,
    ports: list[int],
    *,
    concurrency: int = 200,
    timeout: float = 1.0,
    connect_fn=asyncio.open_connection,
) -> list[PortResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded(port: int) -> PortResult:
        async with semaphore:
            return await _probe(host, port, timeout, connect_fn)

    results = await asyncio.gather(*(bounded(p) for p in ports))
    return sorted(results, key=lambda r: r.port)


def scan_ports(host: str, ports: list[int], **kwargs) -> list[PortResult]:
    """Synchronous convenience wrapper around `scan_ports_async`."""
    return asyncio.run(scan_ports_async(host, ports, **kwargs))
