import http.server
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from recon_agent.cli import _require_authorization

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class _Handler(http.server.BaseHTTPRequestHandler):
    """Minimal local HTTP server with intentionally weak security headers,
    used so the CLI tests exercise a real (loopback-only) HTTP round trip
    without any external network access.
    """

    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\n"
            self.send_response_only(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b"<html><body>ok</body></html>"
        self.send_response_only(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "TestServer/1.0")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - matches base class signature
        pass


@pytest.fixture()
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join()


def _run_cli(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "recon_agent.cli", *args],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_runs_against_local_server_and_reports_missing_headers(local_server):
    port = local_server.server_address[1]
    result = _run_cli(f"http://127.0.0.1:{port}/")
    assert result.returncode == 0, result.stderr
    assert "Overall risk" in result.stdout
    assert "Missing or weak 'Content-Security-Policy'" in result.stdout
    assert "Server header discloses" in result.stdout
    assert "robots.txt discloses a potentially sensitive path: /admin" in result.stdout


def test_cli_json_output_is_valid(local_server):
    port = local_server.server_address[1]
    result = _run_cli(f"http://127.0.0.1:{port}/", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["target"] == f"http://127.0.0.1:{port}/"
    assert payload["planner"] == "DeterministicPlanner"
    assert any(f["category"] == "security_headers" for f in payload["findings"])


def test_require_authorization_allows_localhost():
    _require_authorization("http://localhost:8000", authorized=False)


def test_require_authorization_blocks_remote_without_flag():
    with pytest.raises(SystemExit):
        _require_authorization("https://example.com", authorized=False)


def test_require_authorization_allows_remote_with_flag():
    _require_authorization("https://example.com", authorized=True)
