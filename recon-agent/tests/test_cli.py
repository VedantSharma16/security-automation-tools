from __future__ import annotations

import json

from recon_agent import cli
from recon_agent.agent import ReconReport, ToolCallTrace
from recon_agent.scoring import RiskAssessment


def _fake_report():
    return ReconReport(
        target="example.com",
        is_live=False,
        trace=[ToolCallTrace(tool="dns_lookup", arguments={"record_type": "A"}, result={})],
        narrative="All clear.",
        risk=RiskAssessment(score=0, severity="info", findings=[]),
    )


class FakeAgent:
    def __init__(self, *args, **kwargs):
        pass

    def run(self):
        return _fake_report()


def test_refuses_to_run_without_authorization_flag(capsys):
    exit_code = cli.main(["example.com"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Refusing to run" in captured.err


def test_runs_and_prints_markdown_with_authorization(monkeypatch, capsys):
    monkeypatch.setattr(cli, "ReconAgent", FakeAgent)

    exit_code = cli.main(["example.com", "--i-have-authorization"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "# Passive recon report: example.com" in captured.out


def test_json_flag_prints_valid_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "ReconAgent", FakeAgent)

    exit_code = cli.main(["example.com", "--i-have-authorization", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["target"] == "example.com"
    assert payload["risk"]["severity"] == "info"
