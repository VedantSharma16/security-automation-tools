"""Fetcher tests against a local, loopback-only HTTP server -- no real network access."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webscan import fetcher


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - silence test server logging
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", "nginx/1.18.0")
            self.send_header("Set-Cookie", "session=abc; Path=/")
            self.send_header("Set-Cookie", "tracking=xyz; Secure; HttpOnly; SameSite=Lax")
            self.end_headers()
            self.wfile.write(b"hello")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/notfound":
            self.send_response(404)
            self.send_header("X-Powered-By", "Express")
            self.end_headers()
            self.wfile.write(b"nope")
        elif self.path == "/cors":
            self.send_response(200)
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def server_url():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_fetch_target_basic_headers_and_cookies(server_url):
    target = fetcher.fetch_target(server_url + "/", send_cors_probe=False)
    assert target.status_code == 200
    assert target.get_header("server") == "nginx/1.18.0"
    assert len(target.cookies) == 2
    assert any("session=abc" in c for c in target.cookies)


def test_fetch_target_follows_redirect(server_url):
    target = fetcher.fetch_target(server_url + "/redirect", send_cors_probe=False)
    assert target.status_code == 200
    assert target.final_url == server_url + "/"


def test_fetch_target_captures_error_response_headers(server_url):
    target = fetcher.fetch_target(server_url + "/notfound", send_cors_probe=False)
    assert target.status_code == 404
    assert target.get_header("x-powered-by") == "Express"


def test_fetch_target_cors_probe_reflects_origin(server_url):
    target = fetcher.fetch_target(server_url + "/cors", send_cors_probe=True, cors_test_origin="https://evil.test")
    assert target.cors_test_headers is not None
    assert target.cors_test_headers.get("access-control-allow-origin") == "https://evil.test"
    assert target.cors_test_headers.get("access-control-allow-credentials") == "true"


def test_fetch_target_no_cors_probe_when_disabled(server_url):
    target = fetcher.fetch_target(server_url + "/cors", send_cors_probe=False)
    assert target.cors_test_headers is None
