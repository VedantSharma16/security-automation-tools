from pathlib import Path

import pytest
import yaml

from sigma_engine.cli import main
from sigma_engine.rule import load_rules
from sigma_engine.testing import TestSuiteError, run_rule_tests

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR, TESTS_DIR = ROOT / "rules", ROOT / "rule-tests"
SAMPLE = ROOT / "samples" / "intrusion_chain.jsonl"
PS_ID = "73c7c4e3-25c5-4ed9-8da1-64bfb7da6247"


def test_bundled_rule_tests_all_pass_with_full_coverage():
    rules = load_rules([RULES_DIR])
    report = run_rule_tests(rules, [TESTS_DIR])
    assert report.ok, [f.name for f in report.failures]
    assert report.coverage(len(rules)) == 1.0
    assert report.rules_missing_negative == []


def test_failing_case_and_orphans_are_reported(tmp_path):
    (tmp_path / "t.yml").write_text(yaml.safe_dump({
        "rule_id": PS_ID,
        "cases": [{"name": "wrong expectation", "expect": "match", "event": {"Image": "notepad.exe"}}],
    }))
    (tmp_path / "o.yml").write_text(yaml.safe_dump({
        "rule_id": "00000000-0000-0000-0000-000000000000",
        "cases": [{"expect": "match", "event": {}}],
    }))
    rules = load_rules([RULES_DIR])
    report = run_rule_tests(rules, [tmp_path])
    assert [f.name for f in report.failures] == ["wrong expectation"]
    assert len(report.orphan_files) == 1
    assert len(report.untested_rules) == len(rules) - 1
    assert [r.id for r in report.rules_missing_negative] == [PS_ID]
    assert not report.ok


@pytest.mark.parametrize(
    "doc",
    [{"cases": []}, {"rule_id": PS_ID, "cases": []}, {"rule_id": PS_ID, "cases": [{"expect": "maybe", "event": {}}]}],
)
def test_malformed_suites(tmp_path, doc):
    (tmp_path / "t.yml").write_text(yaml.safe_dump(doc))
    with pytest.raises(TestSuiteError):
        run_rule_tests([], [tmp_path])


def test_cli_scan_gate_and_outputs(tmp_path, capsys):
    out = tmp_path / "r.json"
    assert main(["scan", str(SAMPLE), "-r", str(RULES_DIR), "-f", "json", "-o", str(out)]) == 0
    assert '"alerts"' in out.read_text()
    assert main(["scan", str(SAMPLE), "-r", str(RULES_DIR), "--fail-on", "critical"]) == 1
    assert "# Detection Scan Report" in capsys.readouterr().out


def test_cli_lint_test_coverage(capsys):
    assert main(["lint", str(RULES_DIR), "--strict"]) == 0
    assert main(["test", "-r", str(RULES_DIR), "-t", str(TESTS_DIR), "--min-coverage", "100"]) == 0
    assert main(["coverage", str(RULES_DIR)]) == 0
    assert "# ATT&CK Coverage" in capsys.readouterr().out


def test_cli_errors_return_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing.jsonl"), "-r", str(RULES_DIR)]) == 2
    bad = tmp_path / "bad.yml"
    bad.write_text("title: x\ndetection: {condition: nope, sel: {A: 1}}\n")
    assert main(["scan", str(SAMPLE), "-r", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err
