"""The agent's toolbox: small, safe, read-only/lightweight recon primitives.

Every network-facing function is injectable (``http_get``, ``resolve``,
``tcp_connect``, ``tls_info``) so ``ToolBox`` can be exercised fully offline
in tests, while defaulting to real stdlib-only implementations (no third
party HTTP/scanning libraries) for actual use.

Tools are deliberately passive or minimally invasive: header/robots.txt
fetches, a DNS lookup, a TLS handshake inspection, and a TCP-connect scan
limited to a short, curated port list. There is no exploitation, brute
forcing, or fuzzing here.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from .security_headers import grade

DEFAULT_TIMEOUT = 3.0
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443]


@dataclass
class ToolResult:
    tool: str
    ok: bool
    data: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return {"tool": self.tool, "ok": self.ok, "data": self.data, "error": self.error}


def default_http_get(url: str, timeout: float = DEFAULT_TIMEOUT):
    """GET ``url`` and return ``(status, headers, body)``.

    Lets ``urllib.error.HTTPError`` propagate for non-2xx responses (it still
    carries ``.code``/``.headers``) so callers can decide how to treat them.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "web-recon-agent/0.1 (+authorized-recon)"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - deliberate recon tool
        return response.status, dict(response.headers.items()), response.read()


def default_resolve(host: str) -> list[str]:
    _, _, addresses = socket.gethostbyname_ex(host)
    return addresses


def default_tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def default_tls_info(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()
            cipher = tls_sock.cipher()
    return {"protocol": protocol, "cipher": cipher[0] if cipher else None, "cert": cert}


HttpGetFn = Callable[[str, float], tuple[int, dict, bytes]]
ResolveFn = Callable[[str], list[str]]
ConnectFn = Callable[[str, int, float], bool]
TlsFn = Callable[[str, int, float], dict]


def _root_url(url: str, path: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _parse_robots_disallow(text: str) -> list[str]:
    paths: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() == "disallow":
            value = value.strip()
            if value and value not in paths:
                paths.append(value)
    return paths[:25]


class ToolBox:
    """Holds the agent's tools plus a little short-term memory.

    ``fetch_headers`` caches the last headers/scheme/port it observed so
    ``grade_security_headers`` and ``port_scan`` can be called with no
    arguments (as an LLM planner naturally would) and still have something
    sensible to act on.
    """

    def __init__(
        self,
        http_get: HttpGetFn = default_http_get,
        resolve: ResolveFn = default_resolve,
        tcp_connect: ConnectFn = default_tcp_connect,
        tls_info: TlsFn = default_tls_info,
    ):
        self._http_get = http_get
        self._resolve = resolve
        self._tcp_connect = tcp_connect
        self._tls_info = tls_info
        self._last_headers: dict | None = None
        self._last_scheme: str | None = None
        self._last_port: int | None = None

    def dns_lookup(self, host: str) -> ToolResult:
        try:
            addresses = self._resolve(host)
        except OSError as exc:
            return ToolResult("dns_lookup", False, {"host": host}, error=str(exc))
        return ToolResult("dns_lookup", True, {"host": host, "addresses": list(addresses)})

    def fetch_headers(self, url: str) -> ToolResult:
        try:
            status, headers, _body = self._http_get(url, DEFAULT_TIMEOUT)
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = dict(exc.headers.items()) if exc.headers else {}
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return ToolResult("fetch_headers", False, {"url": url}, error=str(exc))

        parsed = urlparse(url)
        self._last_headers = headers
        self._last_scheme = parsed.scheme
        self._last_port = parsed.port
        return ToolResult("fetch_headers", True, {"url": url, "status": status, "headers": dict(headers)})

    def fetch_robots_txt(self, url: str) -> ToolResult:
        robots_url = _root_url(url, "/robots.txt")
        try:
            status, _headers, body = self._http_get(robots_url, DEFAULT_TIMEOUT)
        except urllib.error.HTTPError as exc:
            # A missing robots.txt (404, etc.) is a normal, informative result,
            # not a tool failure.
            return ToolResult("fetch_robots_txt", True, {"url": robots_url, "status": exc.code, "disallowed_paths": []})
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return ToolResult("fetch_robots_txt", False, {"url": robots_url}, error=str(exc))

        text = body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else str(body)
        disallowed = _parse_robots_disallow(text) if status == 200 else []
        return ToolResult("fetch_robots_txt", True, {"url": robots_url, "status": status, "disallowed_paths": disallowed})

    def check_tls(self, host: str, port: int = 443) -> ToolResult:
        try:
            info = self._tls_info(host, port, DEFAULT_TIMEOUT)
        except (OSError, TimeoutError) as exc:
            return ToolResult("check_tls", False, {"host": host, "port": port}, error=str(exc))
        return ToolResult("check_tls", True, {"host": host, "port": port, **info})

    def grade_security_headers(self, headers: dict | None = None, scheme: str | None = None) -> ToolResult:
        headers = headers if headers is not None else self._last_headers
        scheme = scheme or self._last_scheme or "https"
        if headers is None:
            return ToolResult("grade_security_headers", False, {}, error="No headers available; call fetch_headers first.")
        return ToolResult("grade_security_headers", True, grade(dict(headers), scheme))

    def port_scan(self, host: str, ports: list[int] | None = None) -> ToolResult:
        ports = list(ports) if ports else self._default_ports()
        open_ports = [p for p in ports if self._tcp_connect(host, p, 0.5)]
        return ToolResult("port_scan", True, {"host": host, "scanned": ports, "open_ports": open_ports})

    def _default_ports(self) -> list[int]:
        ports = set(COMMON_PORTS)
        if self._last_port:
            ports.add(self._last_port)
        return sorted(ports)
