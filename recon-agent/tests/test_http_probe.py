"""Integration tests against a local HTTP server (127.0.0.1) — no external
network access is exercised. TLS probing is tested with mocked sockets
since standing up a real TLS server is unnecessary ceremony for this."""

from __future__ import annotations

import socket
import ssl
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import pytest

from recon_agent.http_probe import probe_tls, probe_url


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def do_GET(self):
        if self.path == "/notfound":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Test-Header", "hello")
        self.end_headers()
        self.wfile.write(b"ok")


@contextmanager
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


def test_probe_url_success_captures_status_and_headers():
    with local_server() as base_url:
        result = probe_url(f"{base_url}/", timeout=2.0)

    assert result.ok is True
    assert result.status_code == 200
    assert result.headers.get("X-Test-Header") == "hello"
    assert result.elapsed_ms is not None and result.elapsed_ms >= 0
    assert result.error is None


def test_probe_url_http_error_is_still_ok():
    with local_server() as base_url:
        result = probe_url(f"{base_url}/notfound", timeout=2.0)

    assert result.ok is True
    assert result.status_code == 404


def test_probe_url_connection_refused_is_not_ok():
    # Nothing is listening on this port.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]

    result = probe_url(f"http://127.0.0.1:{closed_port}/", timeout=2.0)
    assert result.ok is False
    assert result.error is not None
    assert result.status_code is None


def test_probe_tls_success():
    fake_cert = {
        "notAfter": "Jan  1 00:00:00 2099 GMT",
        "issuer": ((("organizationName", "Test CA"),),),
    }
    fake_ssl_sock = MagicMock()
    fake_ssl_sock.getpeercert.return_value = fake_cert
    fake_ssl_sock.version.return_value = "TLSv1.3"
    fake_ssl_sock.__enter__.return_value = fake_ssl_sock
    fake_ssl_sock.__exit__.return_value = False

    fake_context = MagicMock()
    fake_context.wrap_socket.return_value = fake_ssl_sock

    fake_plain_sock = MagicMock()
    fake_plain_sock.__enter__.return_value = fake_plain_sock
    fake_plain_sock.__exit__.return_value = False

    with patch("socket.create_connection", return_value=fake_plain_sock), patch(
        "ssl.create_default_context", return_value=fake_context
    ):
        result = probe_tls("example.com", port=443, timeout=2.0)

    assert result.ok is True
    assert result.version == "TLSv1.3"
    assert result.issuer == "organizationName=Test CA"
    assert result.days_until_expiry is not None and result.days_until_expiry > 0


def test_probe_tls_failure():
    with patch("socket.create_connection", side_effect=OSError("connection refused")):
        result = probe_tls("example.com", port=443, timeout=2.0)

    assert result.ok is False
    assert "connection refused" in result.error
