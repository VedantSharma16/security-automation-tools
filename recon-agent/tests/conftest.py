"""Shared test fixtures: tiny local TCP/TLS servers so the tool tests exercise
real sockets against 127.0.0.1 instead of hitting the network or mocking
`socket` itself."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class BannerServer:
    """Accepts one connection, writes `payload`, then closes."""

    def __init__(self, payload: bytes):
        self.port = _free_port()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(1)
        self._payload = payload
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            if self._payload:
                conn.sendall(self._payload)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def ssh_banner_server():
    server = BannerServer(b"SSH-2.0-OpenSSH_7.2\r\n")
    yield server
    server.close()


@pytest.fixture
def silent_server():
    server = BannerServer(b"")
    yield server
    server.close()


@pytest.fixture
def closed_port():
    """A port nothing is listening on (bound then immediately released)."""
    return _free_port()


class HttpServer:
    """Serves one canned HTTP response to every connection it accepts."""

    def __init__(self, response: bytes, use_tls: bool = False, cert_files: tuple[str, str] | None = None):
        self.port = _free_port()
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind(("127.0.0.1", self.port))
        raw_sock.listen(1)
        self._sock = raw_sock
        self._response = response
        self._use_tls = use_tls
        self._ctx = None
        if use_tls:
            cert_file, key_file = cert_files
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ctx.load_cert_chain(cert_file, key_file)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            if self._ctx:
                conn = self._ctx.wrap_socket(conn, server_side=True)
            conn.recv(4096)
            conn.sendall(self._response)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def http_server():
    body = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    server = HttpServer(body)
    yield server
    server.close()


def _generate_self_signed_cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )

    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)


@pytest.fixture
def tls_server(tmp_path):
    pytest.importorskip("cryptography")
    cert_file, key_file = _generate_self_signed_cert(tmp_path)
    body = b"HTTP/1.1 200 OK\r\nServer: nginx/1.4.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    server = HttpServer(body, use_tls=True, cert_files=(cert_file, key_file))
    yield server
    server.close()
