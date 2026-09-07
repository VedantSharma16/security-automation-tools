"""Best-effort HTTP(S) security-header audit for open web ports.

Issues a single HEAD request per port (stdlib `http.client`, no extra
dependency) purely to read response headers — no crawling, no POST bodies,
no auth attempts. The fetch function is injectable so tests never touch the
network.
"""

from __future__ import annotations

from .fingerprint import Finding

# port -> whether it should be probed over TLS
WEB_PORTS = {80: False, 8000: False, 8080: False, 443: True, 8443: True}

_OPTIONAL_HEADERS = {
    "content-security-policy": (
        "low",
        "Content-Security-Policy is missing, which weakens defense-in-depth "
        "against XSS and data-injection attacks.",
    ),
    "x-content-type-options": (
        "low",
        "X-Content-Type-Options: nosniff is missing, allowing MIME-sniffing "
        "in some browsers.",
    ),
    "referrer-policy": (
        "info",
        "Referrer-Policy is not set; the browser default may leak full URLs "
        "to third parties on outbound links.",
    ),
}


def default_fetch(host: str, port: int, use_tls: bool, timeout: float = 3.0):
    import http.client

    conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=timeout)
    try:
        conn.request("HEAD", "/")
        response = conn.getresponse()
        headers = {k.lower(): v for k, v in response.getheaders()}
        return response.status, headers
    finally:
        conn.close()


def audit_headers(host: str, port: int, use_tls: bool, *, fetch_fn=default_fetch) -> list[Finding]:
    try:
        status, headers = fetch_fn(host, port, use_tls)
    except OSError:
        return []

    findings: list[Finding] = []

    if not use_tls:
        findings.append(
            Finding(
                type="missing_transport_security",
                severity="medium",
                port=port,
                title="Plaintext HTTP",
                detail=f"Port {port} served HTTP without TLS (status {status}).",
                recommendation="Serve this application over HTTPS and redirect "
                "HTTP to HTTPS.",
            )
        )
    elif "strict-transport-security" not in headers:
        findings.append(
            Finding(
                type="missing_header",
                severity="medium",
                port=port,
                title="Missing Strict-Transport-Security",
                detail=f"HTTPS response on port {port} did not set HSTS.",
                recommendation="Add Strict-Transport-Security with a long "
                "max-age to prevent protocol-downgrade attacks.",
            )
        )

    has_csp = "content-security-policy" in headers
    if "x-frame-options" not in headers and not has_csp:
        findings.append(
            Finding(
                type="missing_header",
                severity="low",
                port=port,
                title="Missing X-Frame-Options",
                detail="Neither X-Frame-Options nor a Content-Security-Policy "
                "is set.",
                recommendation="Set X-Frame-Options: DENY (or a CSP "
                "frame-ancestors directive) to prevent clickjacking.",
            )
        )

    for header, (severity, detail) in _OPTIONAL_HEADERS.items():
        if header not in headers:
            findings.append(
                Finding(
                    type="missing_header",
                    severity=severity,
                    port=port,
                    title=f"Missing {header}",
                    detail=detail,
                    recommendation=f"Set the {header} response header.",
                )
            )

    server = headers.get("server", "")
    if server and any(ch.isdigit() for ch in server):
        findings.append(
            Finding(
                type="information_disclosure",
                severity="info",
                port=port,
                title="Verbose Server header",
                detail=f"Server header discloses version information: {server!r}",
                recommendation="Suppress or generalize the Server header to "
                "avoid aiding version-targeted exploitation.",
            )
        )

    return findings


def audit_open_ports(host: str, open_ports: list[int], *, fetch_fn=default_fetch) -> list[Finding]:
    findings: list[Finding] = []
    for port in open_ports:
        if port not in WEB_PORTS:
            continue
        findings.extend(audit_headers(host, port, WEB_PORTS[port], fetch_fn=fetch_fn))
    return findings
