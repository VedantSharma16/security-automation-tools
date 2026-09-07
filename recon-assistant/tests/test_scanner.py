"""Scanner tests use a fake asyncio-stream connect_fn so they run fully
offline and deterministically instead of touching real sockets."""

import asyncio

from recon_assistant.scanner import scan_ports_async


class FakeReader:
    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)

    async def read(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class FakeWriter:
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def make_connect_fn(behaviors: dict[int, object]):
    """behaviors: port -> "refused" | list[bytes] (banner chunks, [] for silent-open)."""

    async def connect_fn(host: str, port: int):
        behavior = behaviors.get(port, "refused")
        if behavior == "refused":
            raise ConnectionRefusedError(f"refused: {port}")
        return FakeReader(list(behavior)), FakeWriter()

    return connect_fn


def test_open_port_with_banner():
    connect_fn = make_connect_fn({22: [b"SSH-2.0-OpenSSH_9.6\r\n"]})
    results = asyncio.run(scan_ports_async("host", [22], connect_fn=connect_fn))
    assert len(results) == 1
    assert results[0].open is True
    assert results[0].banner == "SSH-2.0-OpenSSH_9.6"


def test_closed_port():
    connect_fn = make_connect_fn({})
    results = asyncio.run(scan_ports_async("host", [9999], connect_fn=connect_fn))
    assert results[0].open is False
    assert results[0].banner == ""


def test_http_port_sends_probe_when_silent():
    connect_fn = make_connect_fn({80: [b"", b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"]})
    results = asyncio.run(scan_ports_async("host", [80], connect_fn=connect_fn))
    assert results[0].open is True
    assert "HTTP/1.1 200 OK" in results[0].banner


def test_results_are_sorted_by_port():
    connect_fn = make_connect_fn({443: [b"x"], 22: [b"y"]})
    results = asyncio.run(scan_ports_async("host", [443, 22], connect_fn=connect_fn))
    assert [r.port for r in results] == [22, 443]


def test_concurrency_limit_is_respected():
    max_concurrent = 0
    current = 0

    async def connect_fn(host, port):
        nonlocal max_concurrent, current
        current += 1
        max_concurrent = max(max_concurrent, current)
        await asyncio.sleep(0.01)
        current -= 1
        return FakeReader([b"banner"]), FakeWriter()

    results = asyncio.run(
        scan_ports_async("host", list(range(20)), concurrency=5, connect_fn=connect_fn)
    )
    assert len(results) == 20
    assert max_concurrent <= 5
