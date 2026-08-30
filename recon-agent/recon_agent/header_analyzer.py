"""Rule-based analysis of HTTP response headers for common misconfigurations.

Pure functions over a headers dict — no network I/O — so this module is
fully deterministic and cheap to unit test exhaustively.
"""

from __future__ import annotations

import re

from .models import Finding, ProbeResult

_SERVER_VERSION_RE = re.compile(r"[\d.]{2,}")


def _get(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
    lowered = {k.lower(): v for k, v in headers.items()}
    return lowered.get(name.lower())


def _finding(id_, title, severity, category, evidence, recommendation, url) -> Finding:
    return Finding(
        id=id_,
        title=title,
        severity=severity,
        category=category,
        evidence=evidence,
        recommendation=recommendation,
        source_url=url,
    )


def analyze_headers(probe: ProbeResult) -> list[Finding]:
    """Inspect one probe's response headers and return security findings."""
    if not probe.ok:
        return []

    headers = probe.headers
    is_https = probe.url.lower().startswith("https://")
    findings: list[Finding] = []

    if is_https and _get(headers, "Strict-Transport-Security") is None:
        findings.append(
            _finding(
                "hdr-no-hsts",
                "Missing Strict-Transport-Security header",
                "medium",
                "transport-security",
                "No Strict-Transport-Security header on an HTTPS response.",
                "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
                "to prevent protocol-downgrade and cookie-hijack attacks over plain HTTP.",
                probe.url,
            )
        )

    if _get(headers, "Content-Security-Policy") is None:
        findings.append(
            _finding(
                "hdr-no-csp",
                "Missing Content-Security-Policy header",
                "medium",
                "content-security",
                "No Content-Security-Policy header present.",
                "Define a CSP to restrict script/style/frame sources and reduce the "
                "blast radius of any XSS that does slip through.",
                probe.url,
            )
        )

    xcto = _get(headers, "X-Content-Type-Options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        findings.append(
            _finding(
                "hdr-no-xcto",
                "Missing or invalid X-Content-Type-Options header",
                "low",
                "content-security",
                f"X-Content-Type-Options={xcto!r}",
                "Send `X-Content-Type-Options: nosniff` to stop browsers from "
                "MIME-sniffing responses into an executable content type.",
                probe.url,
            )
        )

    xfo = _get(headers, "X-Frame-Options")
    csp = _get(headers, "Content-Security-Policy") or ""
    if xfo is None and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                "hdr-no-frame-protection",
                "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
                "medium",
                "content-security",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was found.",
                "Send `X-Frame-Options: DENY` (or a CSP `frame-ancestors` directive) "
                "unless the page must be embeddable in a third-party frame.",
                probe.url,
            )
        )

    if _get(headers, "Referrer-Policy") is None:
        findings.append(
            _finding(
                "hdr-no-referrer-policy",
                "Missing Referrer-Policy header",
                "low",
                "information-disclosure",
                "No Referrer-Policy header present.",
                "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) "
                "to avoid leaking full URLs to third-party destinations.",
                probe.url,
            )
        )

    server = _get(headers, "Server")
    if server and _SERVER_VERSION_RE.search(server):
        findings.append(
            _finding(
                "hdr-server-version-disclosure",
                "Server header discloses software/version",
                "low",
                "information-disclosure",
                f"Server: {server}",
                "Suppress or generalize the Server header — a version string makes it "
                "trivial to match the host against known CVEs.",
                probe.url,
            )
        )

    powered_by = _get(headers, "X-Powered-By")
    if powered_by:
        findings.append(
            _finding(
                "hdr-powered-by-disclosure",
                "X-Powered-By header discloses backend technology",
                "low",
                "information-disclosure",
                f"X-Powered-By: {powered_by}",
                "Remove the X-Powered-By header at the framework/proxy level.",
                probe.url,
            )
        )

    acao = _get(headers, "Access-Control-Allow-Origin")
    acac = _get(headers, "Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.strip().lower() == "true":
        findings.append(
            _finding(
                "hdr-cors-wildcard-with-credentials",
                "CORS wildcard origin combined with credentials",
                "critical",
                "cors",
                "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                "Browsers reject this combination, but some clients/proxies don't — "
                "replace the wildcard with an explicit allow-list of trusted origins.",
                probe.url,
            )
        )
    elif acao == "*":
        findings.append(
            _finding(
                "hdr-cors-wildcard",
                "CORS allows any origin",
                "low",
                "cors",
                "Access-Control-Allow-Origin: *",
                "Scope Access-Control-Allow-Origin to the specific origins that need "
                "cross-origin access, if this endpoint is not intentionally public.",
                probe.url,
            )
        )

    for cookie in _iter_set_cookie(headers):
        lowered = cookie.lower()
        missing = [
            flag
            for flag, needle in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
            if needle not in lowered
        ]
        if missing and is_https:
            findings.append(
                _finding(
                    "hdr-cookie-missing-flags",
                    "Set-Cookie missing recommended security flags",
                    "medium",
                    "session-security",
                    f"Set-Cookie: {cookie.split(';')[0]}; missing {', '.join(missing)}",
                    "Set Secure, HttpOnly, and SameSite on session/auth cookies to limit "
                    "exposure to network sniffing, XSS-driven theft, and CSRF.",
                    probe.url,
                )
            )

    return findings


def _iter_set_cookie(headers: dict) -> list[str]:
    """Return every Set-Cookie header value (there can be more than one)."""
    return [v for k, v in headers.items() if k.lower() == "set-cookie"]
