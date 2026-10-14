from pathlib import Path

import pytest
from sigmalite.cli import main
from sigmalite.engine import evaluate_events, read_jsonl, summarize
from sigmalite.rules import RuleError, compile_rule, load_rules

ROOT = Path(__file__).parent.parent
RULES = ROOT / "rules"
EVENTS = Path(__file__).parent / "fixtures" / "events.jsonl"


def run(min_level="informational"):
    rules = load_rules(RULES)
    with open(EVENTS) as f:
        return evaluate_events(rules, read_jsonl(f), min_level)


def test_expected_detections_by_line():
    got = {(m.line, m.rule.title) for m in run()}
    assert got == {
        (1, "Encoded PowerShell Command"),
        (2, "Office Application Spawning Shell"),
        (3, "Credential Dumping via comsvcs MiniDump"),
        (4, "Inbound RDP From Public Address"),
        (6, "Certutil Used As Downloader"),
    }


def test_benign_and_private_rdp_not_flagged():
    lines = {m.line for m in run()}
    assert 5 not in lines and 7 not in lines


def test_min_level_filters():
    assert {m.rule.level for m in run("critical")} == {"critical"}


def test_summary_and_techniques():
    s = summarize(run())
    assert s["total"] == 5
    assert "T1059.001" in s["techniques"]
    assert list(s["by_level"])[0] == "critical"


def test_tactics_extracted():
    r = [r for r in load_rules(RULES) if "Encoded" in r.title][0]
    assert "execution" in r.tactics and "T1027" in r.techniques


def test_invalid_rules_raise():
    with pytest.raises(RuleError):
        compile_rule({"title": "x"})
    with pytest.raises(RuleError):
        compile_rule({"title": "x", "level": "wat", "detection": {"s": {"a": 1}, "condition": "s"}})
    with pytest.raises(RuleError):
        compile_rule({"title": "x", "detection": {"s": {"a": 1}, "condition": "missing"}})


def test_multiple_conditions_are_ored():
    r = compile_rule({"title": "t", "detection": {"a": {"x": 1}, "b": {"y": 1},
                                                  "condition": ["a", "b"]}})
    assert r.evaluate({"y": 1}) and not r.evaluate({"z": 1})


def test_bad_jsonl():
    with pytest.raises(ValueError, match="line 2"):
        list(read_jsonl(['{"a":1}', "{oops"]))
    with pytest.raises(ValueError):
        list(read_jsonl(["[1]"]))


def test_cli_exit_codes(capsys, tmp_path):
    assert main(["--rules", str(RULES), "--events", str(EVENTS)]) == 1
    assert "5 alert(s)" in capsys.readouterr().out
    clean = tmp_path / "c.jsonl"
    clean.write_text('{"Image": "notepad.exe"}\n')
    assert main(["--rules", str(RULES), "--events", str(clean)]) == 0
    assert main(["--rules", str(RULES), "--events", "missing.jsonl"]) == 2


def test_cli_json(capsys):
    import json
    main(["--rules", str(RULES), "--events", str(EVENTS), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["total"] == 5 and len(data["alerts"]) == 5
