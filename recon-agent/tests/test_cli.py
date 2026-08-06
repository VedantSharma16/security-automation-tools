from recon_agent import cli
from recon_agent.models import Finding, ReconReport, ToolResult


def fake_report(with_finding: bool):
    findings = (
        [Finding(tool="dns", severity="high", title="No HTTPS", detail="d", recommendation="r")]
        if with_finding
        else []
    )
    return ReconReport(
        target="example.com",
        tool_results=[ToolResult(tool="dns", data={}, findings=findings)],
        score=85 if with_finding else 100,
        grade="B" if with_finding else "A",
        narrative="Summary.",
    )


def test_main_refuses_to_scan_without_authorized_flag(capsys):
    exit_code = cli.main(["scan", "example.com"])
    assert exit_code == 2
    assert "Refusing to scan" in capsys.readouterr().err


def test_main_exits_clean_when_no_findings(monkeypatch, capsys):
    monkeypatch.setattr(cli.executor, "run", lambda target, agentic=False: fake_report(with_finding=False))

    exit_code = cli.main(["scan", "example.com", "--authorized"])

    assert exit_code == 0
    assert "Recon Report: example.com" in capsys.readouterr().out


def test_main_exits_nonzero_when_findings_present(monkeypatch, capsys):
    monkeypatch.setattr(cli.executor, "run", lambda target, agentic=False: fake_report(with_finding=True))

    exit_code = cli.main(["scan", "example.com", "--authorized"])

    assert exit_code == 1
    assert "No HTTPS" in capsys.readouterr().out


def test_main_writes_json_report_to_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.executor, "run", lambda target, agentic=False: fake_report(with_finding=True))
    out_path = tmp_path / "report.json"

    cli.main(["scan", "example.com", "--authorized", "--format", "json", "--out", str(out_path)])

    payload = out_path.read_text()
    assert '"target": "example.com"' in payload


def test_main_passes_agentic_flag_through(monkeypatch):
    seen = {}

    def fake_run(target, agentic=False):
        seen["agentic"] = agentic
        return fake_report(with_finding=False)

    monkeypatch.setattr(cli.executor, "run", fake_run)

    cli.main(["scan", "example.com", "--authorized", "--agentic"])

    assert seen["agentic"] is True
