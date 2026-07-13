import json

import pytest

from ioc_toolkit.cli import main


def test_extract_json_from_file(tmp_path, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("Beacon to 203.0.113.42 and cve-2024-3094 observed.")

    exit_code = main(["extract", str(sample), "--json"])
    assert exit_code == 0

    out = json.loads(capsys.readouterr().out)
    assert out["ipv4"] == ["203.0.113.42"]
    assert out["cve"] == ["CVE-2024-3094"]


def test_extract_human_readable_no_iocs(tmp_path, capsys):
    sample = tmp_path / "clean.txt"
    sample.write_text("Nothing interesting here.")

    exit_code = main(["extract", str(sample)])
    assert exit_code == 0
    assert "No IOCs found." in capsys.readouterr().out


def test_defang_from_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("1.2.3.4"))
    exit_code = main(["defang"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "1[.]2[.]3[.]4"


def test_refang_from_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("1[.]2[.]3[.]4"))
    exit_code = main(["refang"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "1.2.3.4"


def test_report_json_shape(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sample = tmp_path / "report.txt"
    sample.write_text("Mimikatz used to dump credentials from 203.0.113.42.")

    exit_code = main(["report", str(sample), "--json"])
    assert exit_code == 0

    out = json.loads(capsys.readouterr().out)
    assert set(out.keys()) == {
        "severity",
        "score",
        "narrative",
        "recommended_actions",
        "iocs",
        "attack_techniques",
    }
    assert out["attack_techniques"][0]["keyword"] == "mimikatz"


def test_no_command_exits_with_usage_error():
    with pytest.raises(SystemExit):
        main([])
