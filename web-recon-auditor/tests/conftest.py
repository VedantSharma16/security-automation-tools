import http.server
import threading

import pytest


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    """Serves a small, fixed set of routes so scans are fully offline and
    deterministic. Anything not in ``routes`` falls back to a generic 404,
    which is what lets the soft-404 baselining logic be exercised for real."""

    routes: dict[str, tuple[int, dict[str, str], str]] = {}
    default = (404, {"Content-Type": "text/plain"}, "404 Not Found")

    def log_message(self, fmt, *args):  # silence request logging during tests
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0].lstrip("/")
        status, headers, body = self.routes.get(path, self.default)
        encoded = body.encode("utf-8")
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture
def fixture_server():
    """Starts a background HTTP server with a known, overridable route table.

    Yields (base_url, routes_dict) — mutate ``routes_dict`` before issuing
    requests in the test to control what each path returns.
    """
    routes: dict[str, tuple[int, dict[str, str], str]] = {}

    class Handler(_FixtureHandler):
        pass

    Handler.routes = routes

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", routes
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
