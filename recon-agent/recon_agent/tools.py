"""Recon primitives the agent can call as tools.

Each function is a pure, timeout-bounded network probe — TCP connect scan,
banner grab, HTTP header fetch, or TLS certificate inspection — that
returns a plain dict so it can be logged verbatim in the agent's transcript
and serialized straight to JSON. Nothing here is stealthy or exploitative:
these are the same read-only checks a human analyst runs by hand during the
first few minutes of authorized recon.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone

DEFAULT_TIMEOUT = 1.5

# Deliberately a curated "top ports" list rather than a full 1-65535 sweep —
# this tool is a recon/fingerprinting demo, not a noisy full-range scanner.
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]

HTTP_PORTS = {80, 8080}
TLS_HTTP_PORTS = {443, 8443}

_BANNER_PATTERNS = [
    (re.compile(r"SSH-\d\.\d-OpenSSH[_-]([\w.]+)", re.I), "OpenSSH"),
    (re.compile(r"vsFTPd\s+([\w.]+)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD\s+([\w.]+)", re.I), "ProFTPD"),
    (re.compile(r"Pure-FTPd\s*([\w.]*)", re.I), "Pure-FTPd"),
    (re.compile(r"Postfix", re.I), "Postfix"),
    (re.compile(r"MySQL[\s\x00-\x1f]*([\d.]+)", re.I), "MySQL"),
]

_SERVER_HEADER_PATTERN = re.compile(r"^([A-Za-z][\w.-]*)/([\w.]+)")


def parse_banner(banner: str) -> tuple[str | None, str | None]:
    """Best-effort service/version extraction from a raw banner string."""
    for pattern, service in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.groups() and match.group(1) else None
            return service, version
    return None, None


def tcp_connect_scan(host: str, ports: list[int] | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Attempt a TCP connect() to each port and report which ones accepted."""
    ports = list(ports) if ports is not None else list(TOP_PORTS)
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except (socket.gaierror, OSError):
            pass
        finally:
            sock.close()
    return {"host": host, "ports_scanned": ports, "open_ports": sorted(open_ports)}


def grab_banner(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Connect to a port and read whatever it sends first, unprompted."""
    banner = ""
    error = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        try:
            banner = sock.recv(256).decode(errors="replace").strip()
        except socket.timeout:
            banner = ""
    except OSError as exc:
        error = str(exc)
    finally:
        sock.close()

    service, version = parse_banner(banner) if banner else (None, None)
    return {
        "host": host,
        "port": port,
        "banner": banner,
        "service": service,
        "version": version,
        "error": error,
    }


def http_headers(host: str, port: int = 80, use_tls: bool = False, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Issue a raw HTTP/1.1 GET / and return the status line, headers, and a
    best-effort service/version parse of the Server header."""
    request = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        f"User-Agent: recon-agent/0.1\r\n\r\n"
    )
    raw = b""
    error = None
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(request.encode())
        while len(raw) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    except OSError as exc:
        error = str(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    status_line = None
    headers: dict[str, str] = {}
    server = None
    if raw:
        text = raw.decode(errors="replace")
        head = text.split("\r\n\r\n", 1)[0]
        lines = head.split("\r\n")
        status_line = lines[0] if lines else None
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
        server = headers.get("Server")

    service, version = (None, None)
    if server:
        match = _SERVER_HEADER_PATTERN.match(server)
        if match:
            service, version = match.group(1), match.group(2)
        else:
            service = server

    return {
        "host": host,
        "port": port,
        "status_line": status_line,
        "headers": headers,
        "server": server,
        "service": service,
        "version": version,
        "error": error,
    }


def tls_cert_info(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Inspect the TLS certificate presented on a port without validating it
    (so self-signed lab/test certs are still inspectable), plus negotiated
    protocol/cipher. Certificate field parsing (subject/issuer/expiry)
    requires the optional `cryptography` package; without it those fields
    are reported as unavailable rather than guessed at."""
    result = {
        "host": host,
        "port": port,
        "protocol": None,
        "cipher": None,
        "subject": None,
        "issuer": None,
        "not_after": None,
        "days_until_expiry": None,
        "error": None,
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                result["protocol"] = tls_sock.version()
                cipher = tls_sock.cipher()
                result["cipher"] = cipher[0] if cipher else None
                der = tls_sock.getpeercert(binary_form=True)
                if der:
                    result.update(_parse_certificate(der))
    except OSError as exc:
        result["error"] = str(exc)
    return result


def _parse_certificate(der_bytes: bytes) -> dict:
    try:
        from cryptography import x509
    except ImportError:
        return {"subject": None, "issuer": None, "not_after": None, "days_until_expiry": None}

    cert = x509.load_der_x509_certificate(der_bytes)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
    }
