import json

from attack_surface_mapper import cli
from attack_surface_mapper.models import Finding, OpenPort, Subdomain


def test_no_hosts_discovered_exits_clean(monkeypatch, capsys):
    monkeypatch.setattr(cli.subdomains, "discover", lambda target, timeout: [])
    code = cli.main(["example.com"])
    assert code == cli.EXIT_CLEAN
    assert "No subdomains discovered" in capsys.readouterr().out


def test_passive_only_never_calls_active_checks(monkeypatch):
    monkeypatch.setattr(
        cli.subdomains, "discover",
        lambda target, timeout: [Subdomain(name="www.example.com", ip="10.0.0.1")],
    )
    scan_called = []
    monkeypatch.setattr(cli.portscan, "scan_host", lambda *a, **k: scan_called.append(1))

    code = cli.main(["example.com", "--passive-only"])

    assert code == cli.EXIT_CLEAN
    assert scan_called == []


def test_missing_authorization_flag_skips_active_stage(monkeypatch, capsys):
    monkeypatch.setattr(
        cli.subdomains, "discover",
        lambda target, timeout: [Subdomain(name="www.example.com", ip="10.0.0.1")],
    )
    scan_called = []
    monkeypatch.setattr(cli.portscan, "scan_host", lambda *a, **k: scan_called.append(1))

    code = cli.main(["example.com"])

    assert code == cli.EXIT_CLEAN
    assert scan_called == []
    assert "i-am-authorized" in capsys.readouterr().out


def test_authorized_full_scan_reports_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli.subdomains, "discover",
        lambda target, timeout: [Subdomain(name="www.example.com", ip="10.0.0.1")],
    )
    monkeypatch.setattr(
        cli.portscan, "scan_host",
        lambda host, ports, timeout: [OpenPort(port=3389, service="rdp", sensitive=True)],
    )
    monkeypatch.setattr(
        cli.httpaudit, "fetch_headers", lambda url, timeout: (200, {"server": "nginx"})
    )
    monkeypatch.setattr(cli.httpaudit, "audit_headers", lambda headers, scheme: [])
    monkeypatch.setattr(cli.httpaudit, "audit_banner", lambda headers: [])
    monkeypatch.setattr(
        cli.tlsaudit, "get_certificate", lambda host, timeout: {"notAfter": "fake"}
    )
    monkeypatch.setattr(
        cli.tlsaudit, "check_expiry",
        lambda cert, warn_days: [Finding(category="tls", severity="high", title="x", detail="y")],
    )

    json_out = tmp_path / "out.json"
    code = cli.main(["example.com", "--i-am-authorized", "--json-out", str(json_out)])

    assert code == cli.EXIT_FINDINGS
    data = json.loads(json_out.read_text())
    assert data[0]["host"] == "www.example.com"
    assert data[0]["open_ports"][0]["port"] == 3389


def test_clean_host_exits_zero(monkeypatch):
    monkeypatch.setattr(
        cli.subdomains, "discover",
        lambda target, timeout: [Subdomain(name="www.example.com", ip="10.0.0.1")],
    )
    monkeypatch.setattr(cli.portscan, "scan_host", lambda host, ports, timeout: [])
    monkeypatch.setattr(cli.httpaudit, "fetch_headers", lambda url, timeout: (None, {}))
    monkeypatch.setattr(
        cli.tlsaudit, "get_certificate", lambda host, timeout: None
    )

    code = cli.main(["example.com", "--i-am-authorized"])
    assert code == cli.EXIT_CLEAN


def test_skip_discovery_scans_literal_host(monkeypatch):
    monkeypatch.setattr(
        cli.subdomains, "resolve", lambda hosts, timeout: {"host.internal": "10.0.0.5"}
    )
    monkeypatch.setattr(cli.portscan, "scan_host", lambda host, ports, timeout: [])
    monkeypatch.setattr(cli.httpaudit, "fetch_headers", lambda url, timeout: (None, {}))
    monkeypatch.setattr(cli.tlsaudit, "get_certificate", lambda host, timeout: None)

    code = cli.main(["host.internal", "--skip-discovery", "--i-am-authorized"])
    assert code == cli.EXIT_CLEAN


def test_max_hosts_caps_active_scanning(monkeypatch):
    hosts = [Subdomain(name=f"h{i}.example.com", ip=f"10.0.0.{i}") for i in range(3)]
    monkeypatch.setattr(cli.subdomains, "discover", lambda target, timeout: hosts)

    scanned = []

    def fake_scan_host(host, ports, timeout):
        scanned.append(host)
        return []

    monkeypatch.setattr(cli.portscan, "scan_host", fake_scan_host)
    monkeypatch.setattr(cli.httpaudit, "fetch_headers", lambda url, timeout: (None, {}))
    monkeypatch.setattr(cli.tlsaudit, "get_certificate", lambda host, timeout: None)

    cli.main(["example.com", "--i-am-authorized", "--max-hosts", "1"])

    assert scanned == ["h0.example.com"]


def test_parse_ports_maps_known_and_unknown_ports():
    ports = cli._parse_ports("22, 80, 9999")
    assert ports == {22: "ssh", 80: "http", 9999: "unknown"}
