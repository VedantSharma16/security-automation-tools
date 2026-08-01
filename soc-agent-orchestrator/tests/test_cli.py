import json

from soc_orchestrator import cli
from soc_orchestrator.synthesis import InvestigationReport


def _fake_report():
    return InvestigationReport(
        case_dir="/cases/1",
        incident_description="paged for SSH activity",
        tools_invoked=[],
        overall_severity="high",
        risk_score=45,
        mitre_techniques=[{"id": "T1071", "tactic": "C2", "source": "run_ioc_triage", "name": "App Layer Protocol"}],
        recommended_actions=["Rotate credentials."],
        narrative="Something happened.",
        llm_backed=False,
        generated_at="2026-01-01T00:00:00",
    )


def test_run_investigate_missing_directory_returns_error(tmp_path, capsys):
    parser = cli.build_arg_parser()
    args = parser.parse_args(["investigate", str(tmp_path / "nope")])
    code = cli.run_investigate(args)
    assert code == 1
    assert "no such directory" in capsys.readouterr().err


def test_run_investigate_json_format(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "investigate", lambda **kwargs: _fake_report())
    parser = cli.build_arg_parser()
    args = parser.parse_args(["investigate", str(tmp_path), "--format", "json"])

    code = cli.run_investigate(args)

    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["overall_severity"] == "high"


def test_run_investigate_markdown_format_includes_sections(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "investigate", lambda **kwargs: _fake_report())
    parser = cli.build_arg_parser()
    args = parser.parse_args(["investigate", str(tmp_path), "--format", "markdown"])

    cli.run_investigate(args)

    out = capsys.readouterr().out
    assert "# SOC Investigation Report" in out
    assert "T1071" in out
    assert "Rotate credentials." in out
    assert "Something happened." in out


def test_run_investigate_writes_to_out_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "investigate", lambda **kwargs: _fake_report())
    out_file = tmp_path / "report.md"
    parser = cli.build_arg_parser()
    args = parser.parse_args(["investigate", str(tmp_path), "--out", str(out_file)])

    cli.run_investigate(args)

    assert out_file.exists()
    assert "SOC Investigation Report" in out_file.read_text(encoding="utf-8")


def test_no_llm_flag_forces_offline_planner(tmp_path, monkeypatch):
    captured = {}

    def fake_investigate(**kwargs):
        captured.update(kwargs)
        return _fake_report()

    monkeypatch.setattr(cli, "investigate", fake_investigate)
    parser = cli.build_arg_parser()
    args = parser.parse_args(["investigate", str(tmp_path), "--no-llm"])

    cli.run_investigate(args)

    assert captured["use_llm"] is False


def test_main_requires_a_subcommand():
    import pytest

    with pytest.raises(SystemExit):
        cli.main([])
