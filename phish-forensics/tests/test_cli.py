import json
from pathlib import Path

from phish_forensics import cli

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_cli_missing_file_returns_error(capsys):
    exit_code = cli.main(["--eml", "does-not-exist.eml", "--no-narrative"])
    assert exit_code == 2
    assert "No such file" in capsys.readouterr().err


def test_cli_markdown_happy_path(capsys):
    exit_code = cli.main(["--eml", str(FIXTURES / "phishing_paypal_bec.eml"), "--no-narrative"])
    out = capsys.readouterr().out
    assert exit_code == 1  # CRITICAL/HIGH severity -> non-zero exit for automation gating
    assert "# Phishing Triage Report" in out
    assert "display_name_spoof" not in out  # ids aren't printed, titles are
    assert "impersonates" in out.lower()


def test_cli_json_output(capsys):
    exit_code = cli.main(["--eml", str(FIXTURES / "phishing_paypal_bec.eml"), "--json", "--no-narrative"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["message"]["from_domain"] == "paypa1-support.com"
    assert payload["narrative"] is None
    assert exit_code == 1


def test_cli_benign_email_exits_zero(capsys):
    exit_code = cli.main(["--eml", str(FIXTURES / "benign_newsletter.eml"), "--no-narrative"])
    assert exit_code == 0


def test_cli_writes_json_out_file(tmp_path):
    out_path = tmp_path / "report.json"
    cli.main(
        [
            "--eml",
            str(FIXTURES / "benign_newsletter.eml"),
            "--no-narrative",
            "--json-out",
            str(out_path),
        ]
    )
    payload = json.loads(out_path.read_text())
    assert payload["message"]["from_addr"] == "news@example.com"


def test_cli_includes_offline_narrative_by_default(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cli.main(["--eml", str(FIXTURES / "benign_newsletter.eml")])
    out = capsys.readouterr().out
    assert "offline heuristic summary" in out
