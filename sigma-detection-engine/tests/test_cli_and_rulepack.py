"""End-to-end CLI tests, plus the CI gate for the shipped rule pack."""

import json
from pathlib import Path

from sigmalite.attack import coverage
from sigmalite.cli import main
from sigmalite.rule import load_rules, rule_from_dict
from sigmalite.testing import run_rule_tests

ROOT = Path(__file__).resolve().parent.parent
RULES = str(ROOT / "rules")
EVENTS = str(ROOT / "samples" / "attack_chain.jsonl")


# --------------------------------------------------------------------- rule pack gate


def test_every_shipped_rule_has_passing_tests():
    report = run_rule_tests(load_rules(RULES))
    assert report.ok, report.summary()
    assert not report.untested, report.untested


def test_shipped_rules_are_attack_tagged():
    cov = coverage(load_rules(RULES))
    assert not cov.untagged
    assert "credential_access" in cov.by_tactic and "impact" in cov.by_tactic


def test_test_runner_reports_failures():
    bad = rule_from_dict({
        "title": "Too Narrow",
        "detection": {"sel": {"Image": "*\\evil.exe"}, "condition": "sel"},
        "tests": {"match": [{"Image": "C:\\evil2.exe"}], "no_match": [{"Image": "C:\\evil.exe"}]},
    }).compile()
    report = run_rule_tests([bad])
    assert len(report.failures) == 2
    assert "should fire but did not" in report.summary()
    assert "fired on a benign event" in report.summary()


# --------------------------------------------------------------------- CLI


def test_cli_validate_and_test(capsys):
    assert main(["validate", "--rules", RULES]) == 0
    assert "compiled successfully" in capsys.readouterr().out
    assert main(["test", "--rules", RULES, "--require-tests"]) == 0
    assert "detection test cases passed" in capsys.readouterr().out


def test_cli_coverage(capsys):
    assert main(["coverage", "--rules", RULES]) == 0
    out = capsys.readouterr().out
    assert "# ATT&CK Coverage" in out and "T1003.001" in out


def test_cli_scan_markdown_detects_attack_chain(capsys):
    code = main(["scan", "--rules", RULES, "--events", EVENTS])
    out = capsys.readouterr().out
    assert code == 1  # critical incident present
    assert "CRITICAL · `WS-FIN-07.corp.local` — **multi-stage, escalated**" in out
    assert "Initial Access → Execution" in out
    # benign look-alikes must not appear
    assert "vssadmin list shadows" not in out
    assert "-hashfile" not in out
    assert "inventory.ps1" not in out


def test_cli_scan_json_and_output_file(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    code = main(["scan", "--rules", RULES, "--events", EVENTS, "--format", "json", "-o", str(out_file)])
    assert code == 1
    data = json.loads(out_file.read_text())
    assert data["summary"]["events_scanned"] == 18
    assert data["summary"]["alerts"] == 11
    hosts = [i["host"] for i in data["incidents"]]
    assert hosts[0] == "WS-FIN-07.corp.local"
    assert "web-01" in hosts


def test_cli_fail_on_threshold(capsys):
    assert main(["scan", "--rules", RULES, "--events", EVENTS, "--min-level", "critical",
                 "--fail-on", "critical"]) == 1
    assert main(["scan", "--rules", RULES, "--events", EVENTS, "--min-level", "low",
                 "--window", "0.01", "--fail-on", "critical"]) == 1


def test_cli_errors_return_2(tmp_path, capsys):
    assert main(["validate", "--rules", str(tmp_path / "missing.yml")]) == 2
    bad = tmp_path / "events.jsonl"
    bad.write_text("{not json}\n")
    assert main(["scan", "--rules", RULES, "--events", str(bad)]) == 2
    assert "invalid JSON" in capsys.readouterr().err
