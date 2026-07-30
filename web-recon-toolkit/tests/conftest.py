"""Spins up a local, in-process HTTP server so scanner tests never touch the network."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _ConfigurableHandler(BaseHTTPRequestHandler):
    """Handler whose routes/responses are provided by the test via `server.routes`."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 - silence test server logs
        pass

    def do_GET(self):  # noqa: N802 - required name by BaseHTTPRequestHandler
        routes = self.server.routes  # type: ignore[attr-defined]
        route = routes.get(self.path)

        if route is None:
            route = routes.get("__default__", {"status": 404, "body": b"not found", "headers": {}})

        status = route.get("status", 200)
        body = route.get("body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8")
        headers = route.get("headers", {})
        set_cookies = route.get("set_cookies", [])

        # send_response_only (not send_response) so we don't get an
        # auto-injected Server/Date header polluting fingerprint/disclosure
        # assertions in tests that model a "hardened" target.
        self.send_response_only(status)
        for key, value in headers.items():
            self.send_header(key, value)
        for cookie in set_cookies:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestServer:
    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ConfigurableHandler)
        self.server.routes = {}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def set_routes(self, routes: dict) -> None:
        self.server.routes = routes

    def shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def test_server():
    server = TestServer()
    yield server
    server.shutdown()
