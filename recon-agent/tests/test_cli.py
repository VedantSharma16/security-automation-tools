"""CLI tests, run in-process with recon_agent.net monkeypatched so the whole
offline pipeline runs deterministically and with no real network access.
"""

from __future__ import annotations

import json

from recon_agent import net
from recon_agent.cli import main


def _patch_clean_network(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(net, "resolve_host", lambda host: ["93.184.216.34"] if host == "example.com" else [])
    monkeypatch.setattr(net, "http_get_headers", lambda host, use_https=True, timeout=5.0: (
        200, {h: "1" for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                                "X-Content-Type-Options", "Referrer-Policy"]}
    ))
    monkeypatch.setattr(net, "fetch_tls_certificate", lambda host, port=443, timeout=5.0: (
        {
            "notAfter": "Jan  1 00:00:00 2999 GMT",
            "issuer": [[("organizationName", "Example CA")]],
            "subject": [[("commonName", "example.com")]],
        },
        "TLSv1.3",
    ))
    monkeypatch.setattr(net, "whois_query", lambda domain: None)


def test_cli_human_output_clean_target(monkeypatch, capsys):
    _patch_clean_network(monkeypatch)
    exit_code = main(["--target", "example.com"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "example.com" in output
    assert "INFO" in output
    assert "offline deterministic pipeline" in output


def test_cli_json_output_is_valid_and_complete(monkeypatch, capsys):
    _patch_clean_network(monkeypatch)
    main(["--target", "example.com", "--json"])
    output = capsys.readouterr().out

    payload = json.loads(output)
    assert payload["target"] == "example.com"
    assert payload["agent_backed"] is False
    assert "tool_results" in payload
    assert set(payload["tool_results"].keys()) == {
        "dns_lookup", "subdomain_enum", "http_probe", "tls_probe", "whois_lookup",
    }


def test_cli_flags_missing_security_headers(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(net, "resolve_host", lambda host: ["10.0.0.1"] if host == "insecure.example.com" else [])
    monkeypatch.setattr(net, "http_get_headers", lambda host, use_https=True, timeout=5.0: (200, {"Server": "nginx"}))
    monkeypatch.setattr(net, "fetch_tls_certificate", lambda host, port=443, timeout=5.0: (
        {
            "notAfter": "Jan  1 00:00:00 2999 GMT",
            "issuer": [[("organizationName", "Example CA")]],
            "subject": [[("commonName", "insecure.example.com")]],
        },
        "TLSv1.3",
    ))
    monkeypatch.setattr(net, "whois_query", lambda domain: None)

    main(["--target", "insecure.example.com", "--json"])
    payload = json.loads(capsys.readouterr().out)

    categories = {f["category"] for f in payload["findings"]}
    assert "missing-security-headers" in categories
    assert payload["severity"] in {"low", "medium"}
