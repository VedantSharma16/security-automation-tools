"""Individual passive-recon 'tools' the agent (or the offline pipeline) can call.

Every function takes a plain-string target and returns a small
JSON-serializable dict — this is exactly the shape exposed to the LLM as a
tool call, and the shape the offline deterministic pipeline calls directly.
All actual network access lives in :mod:`recon_agent.net`, so these can be
tested by monkeypatching that module.
"""

from __future__ import annotations

from datetime import datetime, timezone

from recon_agent import net

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)

DEFAULT_SUBDOMAIN_WORDLIST = (
    "www", "mail", "api", "dev", "staging", "test", "admin", "vpn", "portal", "ftp", "internal",
)

SENSITIVE_SUBDOMAINS = {"admin", "vpn", "staging", "dev", "internal", "test", "ftp"}


def dns_lookup(domain: str) -> dict:
    """Resolve A/AAAA records for a domain."""
    addresses = net.resolve_host(domain)
    return {
        "domain": domain,
        "resolved": bool(addresses),
        "addresses": addresses,
    }


def subdomain_enum(domain: str, wordlist: tuple[str, ...] | None = None) -> dict:
    """Attempt to resolve a small built-in wordlist of common subdomains."""
    candidates = tuple(wordlist) if wordlist else DEFAULT_SUBDOMAIN_WORDLIST
    discovered = []
    for label in candidates:
        host = f"{label}.{domain}"
        addresses = net.resolve_host(host)
        if addresses:
            discovered.append({
                "subdomain": host,
                "addresses": addresses,
                "sensitive": label in SENSITIVE_SUBDOMAINS,
            })
    return {"domain": domain, "checked": len(candidates), "discovered": discovered}


def http_probe(host: str, use_https: bool = True) -> dict:
    """Probe a host over HTTP(S) and report headers plus missing security headers."""
    try:
        status, headers = net.http_get_headers(host, use_https=use_https)
    except Exception as exc:  # noqa: BLE001 - unreachable hosts are an expected, reportable outcome
        return {"host": host, "reachable": False, "error": str(exc)}

    missing = [h for h in SECURITY_HEADERS if h not in headers]
    return {
        "host": host,
        "reachable": True,
        "status_code": status,
        "server": headers.get("Server", "unknown"),
        "headers": headers,
        "missing_security_headers": missing,
    }


def tls_probe(host: str, port: int = 443) -> dict:
    """Inspect the TLS certificate and negotiated protocol for a host."""
    try:
        cert, protocol = net.fetch_tls_certificate(host, port=port)
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "reachable": False, "error": str(exc)}

    not_after_raw = cert.get("notAfter")
    days_until_expiry = None
    if not_after_raw:
        expiry = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_until_expiry = (expiry - datetime.now(timezone.utc)).days

    issuer = dict(x[0] for x in cert.get("issuer", ()))
    subject = dict(x[0] for x in cert.get("subject", ()))

    return {
        "host": host,
        "reachable": True,
        "protocol": protocol,
        "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
        "subject_cn": subject.get("commonName", "unknown"),
        "not_after": not_after_raw,
        "days_until_expiry": days_until_expiry,
    }


def whois_lookup(domain: str) -> dict:
    """Look up public WHOIS registration data, if the optional dependency is installed."""
    record = net.whois_query(domain)
    if record is None:
        return {"domain": domain, "available": False, "note": "python-whois not installed"}
    return {
        "domain": domain,
        "available": True,
        "registrar": getattr(record, "registrar", None),
        "creation_date": str(getattr(record, "creation_date", None)),
        "expiration_date": str(getattr(record, "expiration_date", None)),
    }
