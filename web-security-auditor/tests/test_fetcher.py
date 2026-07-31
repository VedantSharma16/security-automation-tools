import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webauditor.fetcher import fetch


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("X-Test", "hello")
        self.send_header("Set-Cookie", "a=1")
        self.send_header("Set-Cookie", "b=2")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture(scope="module")
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    thread.join()


def _base_url(server) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def test_fetch_basic_response(server):
    result = fetch(_base_url(server) + "/")
    assert result.ok
    assert result.status == 200
    assert result.get("X-Test") == "hello"
    assert result.get("x-test") == "hello"  # case-insensitive lookup


def test_fetch_follows_redirects(server):
    result = fetch(_base_url(server) + "/redirect")
    assert result.ok
    assert result.status == 200
    assert result.final_url.endswith("/final")
    assert result.redirect_chain


def test_fetch_captures_repeated_headers(server):
    result = fetch(_base_url(server) + "/")
    assert result.get_all("Set-Cookie") == ["a=1", "b=2"]


def test_fetch_unreachable_host_reports_error():
    result = fetch("http://127.0.0.1:1", timeout=2)
    assert not result.ok
    assert result.status == 0
    assert result.error
