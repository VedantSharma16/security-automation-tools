import json

import pytest

from recon_agent import cli
from recon_agent.agent import ReconRun, ReconSession


def test_cli_refuses_without_authorization(capsys):
    exit_code = cli.main(["--target", "example.com"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Refusing to run" in captured.err


def test_cli_happy_path(monkeypatch, capsys):
    def fake_run_recon(target, **kwargs):
        session = ReconSession(target=target)
        session.record("dns_lookup", {"resolved": True, "ip": "1.2.3.4"})
        return ReconRun(session=session, trace=[{"action": "dns_lookup", "reason": "start"}, {"action": "finish", "reason": "done"}], planner_live=False)

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)

    exit_code = cli.main(["--target", "example.com", "--i-have-authorization", "--no-subdomain-enum"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Target: example.com" in out
    assert "offline heuristic summary" in out


def test_cli_json_output(monkeypatch, capsys):
    def fake_run_recon(target, **kwargs):
        session = ReconSession(target=target)
        session.record("dns_lookup", {"resolved": False, "error": "NXDOMAIN"})
        return ReconRun(session=session, trace=[{"action": "dns_lookup", "reason": "start"}], planner_live=False)

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)

    exit_code = cli.main(["--target", "bad.invalid", "--i-have-authorization", "--json"])
    assert exit_code == 1  # dns failure -> "high" severity -> non-zero exit for automation gating
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["overall_severity"] == "high"
    assert payload["target"] == "bad.invalid"


def test_cli_writes_json_out_file(monkeypatch, tmp_path):
    def fake_run_recon(target, **kwargs):
        session = ReconSession(target=target)
        session.record("dns_lookup", {"resolved": True, "ip": "1.2.3.4"})
        return ReconRun(session=session, trace=[], planner_live=False)

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)
    out_path = tmp_path / "report.json"

    cli.main(["--target", "example.com", "--i-have-authorization", "--no-subdomain-enum", "--json-out", str(out_path)])

    payload = json.loads(out_path.read_text())
    assert payload["target"] == "example.com"


def test_cli_custom_ports_parsed(monkeypatch):
    captured_kwargs = {}

    def fake_run_recon(target, **kwargs):
        captured_kwargs.update(kwargs)
        session = ReconSession(target=target)
        session.record("dns_lookup", {"resolved": True, "ip": "1.2.3.4"})
        return ReconRun(session=session, trace=[], planner_live=False)

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)

    cli.main(["--target", "example.com", "--i-have-authorization", "--no-subdomain-enum", "--ports", "80,443,8080"])
    assert captured_kwargs["ports"] == [80, 443, 8080]
