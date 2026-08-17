"""Tests for recon_agent.tools, with all network I/O monkeypatched via recon_agent.net."""

from __future__ import annotations

import socket

import pytest

from recon_agent import net, tools


def test_dns_lookup_resolved(monkeypatch):
    monkeypatch.setattr(net, "resolve_host", lambda host: ["93.184.216.34"])
    result = tools.dns_lookup("example.com")
    assert result == {"domain": "example.com", "resolved": True, "addresses": ["93.184.216.34"]}


def test_dns_lookup_unresolved(monkeypatch):
    monkeypatch.setattr(net, "resolve_host", lambda host: [])
    result = tools.dns_lookup("nonexistent.example.com")
    assert result["resolved"] is False
    assert result["addresses"] == []


def test_subdomain_enum_reports_only_resolved_hosts(monkeypatch):
    def fake_resolve(host):
        return ["10.0.0.1"] if host in ("www.example.com", "admin.example.com") else []

    monkeypatch.setattr(net, "resolve_host", fake_resolve)
    result = tools.subdomain_enum("example.com", wordlist=("www", "admin", "mail"))

    assert result["checked"] == 3
    subdomains = {entry["subdomain"] for entry in result["discovered"]}
    assert subdomains == {"www.example.com", "admin.example.com"}


def test_subdomain_enum_flags_sensitive_labels(monkeypatch):
    monkeypatch.setattr(net, "resolve_host", lambda host: ["10.0.0.1"])
    result = tools.subdomain_enum("example.com", wordlist=("www", "admin"))

    by_name = {entry["subdomain"]: entry for entry in result["discovered"]}
    assert by_name["www.example.com"]["sensitive"] is False
    assert by_name["admin.example.com"]["sensitive"] is True


def test_http_probe_reports_missing_headers(monkeypatch):
    monkeypatch.setattr(net, "http_get_headers", lambda host, use_https=True, timeout=5.0: (
        200, {"Server": "nginx"}
    ))
    result = tools.http_probe("example.com")

    assert result["reachable"] is True
    assert result["status_code"] == 200
    assert result["server"] == "nginx"
    assert "Strict-Transport-Security" in result["missing_security_headers"]


def test_http_probe_all_security_headers_present(monkeypatch):
    headers = {h: "1" for h in tools.SECURITY_HEADERS}
    headers["Server"] = "nginx"
    monkeypatch.setattr(net, "http_get_headers", lambda host, use_https=True, timeout=5.0: (200, headers))

    result = tools.http_probe("example.com")
    assert result["missing_security_headers"] == []


def test_http_probe_handles_unreachable_host(monkeypatch):
    def raise_error(host, use_https=True, timeout=5.0):
        raise OSError("Name or service not known")

    monkeypatch.setattr(net, "http_get_headers", raise_error)
    result = tools.http_probe("dead.example.com")

    assert result["reachable"] is False
    assert "error" in result


def test_tls_probe_computes_expiry(monkeypatch):
    cert = {
        "notAfter": "Jan  1 00:00:00 2999 GMT",
        "issuer": [[("organizationName", "Example CA")]],
        "subject": [[("commonName", "example.com")]],
    }
    monkeypatch.setattr(net, "fetch_tls_certificate", lambda host, port=443, timeout=5.0: (cert, "TLSv1.3"))

    result = tools.tls_probe("example.com")
    assert result["reachable"] is True
    assert result["protocol"] == "TLSv1.3"
    assert result["issuer"] == "Example CA"
    assert result["subject_cn"] == "example.com"
    assert result["days_until_expiry"] > 300 * 365  # far future fixture


def test_tls_probe_handles_connection_failure(monkeypatch):
    def raise_error(host, port=443, timeout=5.0):
        raise socket.timeout("timed out")

    monkeypatch.setattr(net, "fetch_tls_certificate", raise_error)
    result = tools.tls_probe("dead.example.com")

    assert result["reachable"] is False
    assert "error" in result


def test_whois_lookup_without_dependency(monkeypatch):
    monkeypatch.setattr(net, "whois_query", lambda domain: None)
    result = tools.whois_lookup("example.com")
    assert result == {"domain": "example.com", "available": False, "note": "python-whois not installed"}


def test_whois_lookup_with_record(monkeypatch):
    class FakeRecord:
        registrar = "Example Registrar"
        creation_date = "2000-01-01"
        expiration_date = "2030-01-01"

    monkeypatch.setattr(net, "whois_query", lambda domain: FakeRecord())
    result = tools.whois_lookup("example.com")

    assert result["available"] is True
    assert result["registrar"] == "Example Registrar"
