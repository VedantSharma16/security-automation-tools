import json

from asm import cli, dns_recon, http_headers, subdomain_enum, tls_info
from asm.findings import Finding, Severity


def _patch_network(monkeypatch, subdomain_calls=None):
    monkeypatch.setattr(dns_recon, "resolve_records", lambda domain, timeout=10.0: {"A": ["1.2.3.4"]})
    monkeypatch.setattr(
        dns_recon,
        "build_findings",
        lambda domain, records, resolver=None: [Finding("dns", Severity.INFO, "A records resolved", "1.2.3.4")],
    )

    def fake_query_crtsh(domain, timeout=15.0):
        if subdomain_calls is not None:
            subdomain_calls.append(domain)
        return ["www.example.com"]

    monkeypatch.setattr(subdomain_enum, "query_crtsh", fake_query_crtsh)
    monkeypatch.setattr(
        subdomain_enum,
        "build_findings",
        lambda domain, subdomains: [Finding("subdomains", Severity.INFO, "1 subdomain(s)", "www.example.com")],
    )

    monkeypatch.setattr(
        http_headers, "analyze", lambda domain, timeout=10.0: {"https": None, "http": None}
    )
    monkeypatch.setattr(
        http_headers,
        "build_findings",
        lambda domain, result: [Finding("http_headers", Severity.HIGH, "HTTPS not available", "...")],
    )

    monkeypatch.setattr(tls_info, "get_certificate_info", lambda domain, timeout=10.0: None)
    monkeypatch.setattr(
        tls_info,
        "build_findings",
        lambda domain, info: [Finding("tls", Severity.MEDIUM, "TLS connection failed", "...")],
    )


def test_scan_markdown_output(monkeypatch, capsys):
    _patch_network(monkeypatch)
    exit_code = cli.main(["scan", "example.com"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "# Attack Surface Report: example.com" in out
    assert "HTTPS not available" in out


def test_scan_json_output(monkeypatch, capsys):
    _patch_network(monkeypatch)
    exit_code = cli.main(["scan", "example.com", "--format", "json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["domain"] == "example.com"
    assert report["summary"]["highest_severity"] == "HIGH"


def test_scan_writes_to_output_file(monkeypatch, tmp_path):
    _patch_network(monkeypatch)
    out_file = tmp_path / "report.json"
    exit_code = cli.main(["scan", "example.com", "--format", "json", "--out", str(out_file)])
    assert exit_code == 0
    report = json.loads(out_file.read_text())
    assert report["domain"] == "example.com"


def test_scan_no_subdomains_skips_crtsh_query(monkeypatch, capsys):
    calls = []
    _patch_network(monkeypatch, subdomain_calls=calls)
    cli.main(["scan", "example.com", "--no-subdomains"])
    assert calls == []
    out = capsys.readouterr().out
    assert "Subdomains discovered: 0" in out


def test_scan_continues_when_subdomain_enum_fails(monkeypatch, capsys):
    _patch_network(monkeypatch)

    def failing_query(domain, timeout=15.0):
        raise subdomain_enum.SubdomainEnumError("crt.sh unreachable")

    monkeypatch.setattr(subdomain_enum, "query_crtsh", failing_query)

    exit_code = cli.main(["scan", "example.com"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "warning: subdomain enumeration failed" in captured.err
    assert "# Attack Surface Report" in captured.out
