import json

import pytest

from recon import cli, dns_enum, http_headers, port_scan, tls_check
from recon.dns_enum import ResolvedHost
from recon.findings import Finding
from recon.port_scan import OpenPort


def _patch_all_clean(monkeypatch):
    monkeypatch.setattr(dns_enum, "enumerate_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(dns_enum, "analyze_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(cli, "_resolve_target_ip", lambda target: "203.0.113.10")
    monkeypatch.setattr(port_scan, "scan_ports", lambda *a, **k: [])
    monkeypatch.setattr(port_scan, "analyze_ports", lambda *a, **k: [])
    monkeypatch.setattr(
        http_headers, "fetch_headers", lambda *a, **k: {"status": 200, "headers": {}, "final_url": "https://example.com/"}
    )
    monkeypatch.setattr(http_headers, "analyze_headers", lambda *a, **k: [])
    monkeypatch.setattr(
        tls_check, "get_certificate_info", lambda *a, **k: {"host": "example.com", "port": 443, "trusted": True}
    )
    monkeypatch.setattr(tls_check, "analyze_certificate", lambda *a, **k: [])


def test_cli_clean_scan_exits_zero(monkeypatch, capsys):
    _patch_all_clean(monkeypatch)
    exit_code = cli.main(["example.com"])
    assert exit_code == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "No findings" in out


def test_cli_findings_exit_code_is_one(monkeypatch, capsys):
    _patch_all_clean(monkeypatch)
    monkeypatch.setattr(
        port_scan,
        "analyze_ports",
        lambda *a, **k: [Finding(category="ports", title="Redis exposed", severity="critical", description="d")],
    )
    exit_code = cli.main(["example.com"])
    assert exit_code == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "Redis exposed" in out


def test_cli_min_severity_filters_output(monkeypatch, capsys):
    _patch_all_clean(monkeypatch)
    monkeypatch.setattr(
        dns_enum,
        "analyze_subdomains",
        lambda *a, **k: [Finding(category="dns", title="Info only", severity="info", description="d")],
    )
    exit_code = cli.main(["example.com", "--min-severity", "high"])
    assert exit_code == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Info only" not in out


def test_cli_skip_flags_avoid_calling_modules(monkeypatch):
    calls = []
    monkeypatch.setattr(dns_enum, "enumerate_subdomains", lambda *a, **k: calls.append("dns") or [])
    monkeypatch.setattr(cli, "_resolve_target_ip", lambda target: calls.append("resolve") or "1.2.3.4")
    monkeypatch.setattr(port_scan, "scan_ports", lambda *a, **k: calls.append("ports") or [])
    monkeypatch.setattr(http_headers, "fetch_headers", lambda *a, **k: calls.append("headers") or {"status": 200, "headers": {}, "final_url": "x"})
    monkeypatch.setattr(tls_check, "get_certificate_info", lambda *a, **k: calls.append("tls") or {"host": "x", "port": 443, "trusted": True})

    cli.main(
        [
            "example.com",
            "--no-subdomains",
            "--no-ports",
            "--no-headers",
            "--no-tls",
        ]
    )
    assert calls == []


def test_cli_unresolvable_host_skips_port_scan_gracefully(monkeypatch, capsys):
    _patch_all_clean(monkeypatch)
    monkeypatch.setattr(cli, "_resolve_target_ip", lambda target: None)
    exit_code = cli.main(["example.invalid"])
    assert exit_code == cli.EXIT_CLEAN
    err = capsys.readouterr().err
    assert "could not resolve" in err


def test_cli_writes_json_and_markdown_reports(monkeypatch, tmp_path):
    _patch_all_clean(monkeypatch)
    monkeypatch.setattr(
        port_scan,
        "analyze_ports",
        lambda *a, **k: [Finding(category="ports", title="Redis exposed", severity="critical", description="d")],
    )
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"

    cli.main(["example.com", "--json-out", str(json_path), "--md-out", str(md_path)])

    report = json.loads(json_path.read_text())
    assert report["target"] == "example.com"
    assert report["findings"][0]["title"] == "Redis exposed"
    assert "Redis exposed" in md_path.read_text()
