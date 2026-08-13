from recon_agent import agent as agent_mod
from recon_agent.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def _no_open_ports(host, ports=None):
    return {"host": host, "ports_scanned": ports or [], "open_ports": []}


def test_cli_blocks_unauthorized_public_target(capsys):
    exit_code = main(["--target", "8.8.8.8"])
    assert exit_code == EXIT_ERROR
    assert "--authorized" in capsys.readouterr().err


def test_cli_runs_clean_scan_against_loopback(monkeypatch, capsys):
    monkeypatch.setitem(agent_mod.TOOL_REGISTRY, "tcp_connect_scan", _no_open_ports)

    exit_code = main(["--target", "127.0.0.1", "--no-narrative"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_OK
    assert "127.0.0.1" in out
    assert "NONE" in out


def test_cli_exit_code_reflects_vulnerability_findings(monkeypatch, capsys):
    def scan(host, ports=None):
        return {"host": host, "ports_scanned": ports or [], "open_ports": [21]}

    def banner(host, port):
        return {"host": host, "port": port, "banner": "220 (vsFTPd 2.3.4)", "service": "vsftpd", "version": "2.3.4", "error": None}

    monkeypatch.setitem(agent_mod.TOOL_REGISTRY, "tcp_connect_scan", scan)
    monkeypatch.setitem(agent_mod.TOOL_REGISTRY, "grab_banner", banner)

    exit_code = main(["--target", "127.0.0.1", "--no-narrative", "--no-color"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_FINDINGS
    assert "CVE-2011-2523" in out
    assert "CRITICAL" in out


def test_cli_writes_json_and_markdown_reports(monkeypatch, tmp_path):
    monkeypatch.setitem(agent_mod.TOOL_REGISTRY, "tcp_connect_scan", _no_open_ports)
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"

    main(["--target", "127.0.0.1", "--no-narrative", "--json-out", str(json_path), "--md-out", str(md_path)])

    assert json_path.exists()
    assert '"target": "127.0.0.1"' in json_path.read_text()
    assert md_path.exists()
    assert "# Recon Report: 127.0.0.1" in md_path.read_text()


def test_cli_use_llm_without_api_key_falls_back_to_deterministic(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setitem(agent_mod.TOOL_REGISTRY, "tcp_connect_scan", _no_open_ports)

    exit_code = main(["--target", "127.0.0.1", "--no-narrative", "--use-llm"])

    err = capsys.readouterr().err
    assert exit_code == EXIT_OK
    assert "falling back to the deterministic planner" in err


def test_cli_custom_port_list_is_parsed(monkeypatch):
    seen = {}

    def scan(host, ports=None):
        seen["ports"] = ports
        return {"host": host, "ports_scanned": ports or [], "open_ports": []}

    monkeypatch.setitem(agent_mod.TOOL_REGISTRY, "tcp_connect_scan", scan)

    main(["--target", "127.0.0.1", "--no-narrative", "--ports", "22, 80, 443"])

    assert seen["ports"] == [22, 80, 443]
