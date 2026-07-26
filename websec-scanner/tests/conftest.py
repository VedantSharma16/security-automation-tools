from __future__ import annotations

import socket
import threading

import pytest
from werkzeug.serving import make_server

from vulnerable_app import create_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ServerThread(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self.port = _free_port()
        self.server = make_server("127.0.0.1", self.port, app)

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


@pytest.fixture(scope="session")
def live_target():
    """Base URL of an in-process, deliberately-vulnerable Flask app."""
    app = create_app()
    thread = _ServerThread(app)
    thread.start()
    yield f"http://127.0.0.1:{thread.port}"
    thread.stop()
    thread.join(timeout=5)
