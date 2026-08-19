"""Shared pytest fixtures: a real, local-only HTTP server for end-to-end
transport tests that must not touch the network."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib naming convention)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/1.18.0")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        self.wfile.write(b"<html><body class=wp-content>hello</body></html>")

    def log_message(self, format, *args):  # noqa: A002 (stdlib signature)
        pass  # silence request logging during tests


@pytest.fixture()
def local_http_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
