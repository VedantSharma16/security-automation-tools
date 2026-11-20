from pathlib import Path

import pytest
import yaml

from sigma_engine.rule import RuleError, compile_rule, lint_rule, lint_rules, load_rules

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

BASE = {
    "title": "Test rule",
    "id": "11111111-2222-4333-8444-555555555555",
    "status": "test",
    "description": "d",
    "level": "high",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"},
    "falsepositives": ["none"],
}


def write(tmp_path, doc, name="r.yml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(doc))
    return p


def test_bundled_rules_compile_and_lint_clean():
    rules = load_rules([RULES_DIR])
    assert len(rules) >= 9
    assert lint_rules([RULES_DIR]) == []


def test_attack_tag_parsing():
    rule = compile_rule(BASE)
    assert rule.techniques == ["T1059.001"]
    assert rule.tactics == ["execution"]


def test_evaluate_reports_matched_identifiers():
    doc = dict(BASE, detection={
        "sel_a": {"A": "1"}, "sel_b": {"B": "2"}, "filter": {"C": "3"},
        "condition": "1 of sel_* and not filter",
    })
    rule = compile_rule(doc)
    assert rule.evaluate({"A": "1", "B": "2"}) == (True, ["sel_a", "sel_b"])
    assert rule.evaluate({"A": "1", "C": "3"}) == (False, [])


def test_logsource_filtering():
    rule = compile_rule(BASE)
    ps = {"Image": "C:\\x\\powershell.exe"}
    assert rule.matches(ps)  # unlabelled events are evaluated
    assert rule.matches({**ps, "logsource": {"product": "windows"}})
    assert not rule.matches({**ps, "logsource": {"product": "linux"}})
    assert not rule.matches({**ps, "logsource": {"category": "network_connection"}})


@pytest.mark.parametrize(
    "detection",
    [
        {"selection": {"A": "1"}},  # no condition
        {"condition": "selection"},  # no identifiers
        {"selection": {"A|nope": "1"}, "condition": "selection"},
        {"selection": {"A": "1"}, "condition": "selection and missing"},
    ],
)
def test_compile_errors(detection):
    with pytest.raises(RuleError):
        compile_rule(dict(BASE, detection=detection))


def test_lint_flags_metadata_problems(tmp_path):
    doc = dict(BASE, id="not-a-uuid", level="severe", tags=["attack.T9999", "attack.made_up"])
    doc.pop("falsepositives")
    doc["detection"] = {"selection": {"A": "1"}, "unused": {"B": "2"}, "condition": "selection"}
    msgs = [i.message for i in lint_rule(write(tmp_path, doc))]
    assert any("not a valid UUID" in x for x in msgs)
    assert any("level 'severe'" in x for x in msgs)
    assert any("unknown ATT&CK tag 'attack.made_up'" in x for x in msgs)
    assert any("should be lowercase" in x for x in msgs)
    assert any("falsepositives" in x for x in msgs)
    assert any("'unused' is never used" in x for x in msgs)


def test_lint_reports_invalid_yaml_and_compile_errors(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed")
    assert lint_rule(bad)[0].severity == "error"
    broken = write(tmp_path, dict(BASE, detection={"selection": {"A": "1"}, "condition": "nope"}), "b.yml")
    assert "unknown identifier" in lint_rule(broken)[0].message


def test_lint_detects_duplicate_ids(tmp_path):
    write(tmp_path, BASE, "a.yml")
    write(tmp_path, BASE, "b.yml")
    assert any("duplicate id" in i.message for i in lint_rules([tmp_path]))


def test_load_rules_missing_path():
    with pytest.raises(RuleError):
        load_rules(["/nonexistent/rules"])


def test_tactic_technique_pairing_follows_tag_order():
    doc = dict(BASE, tags=["attack.t1105", "attack.command_and_control", "attack.t1071.001",
                           "attack.defense_evasion", "attack.t1218", "attack.t1140"])
    assert compile_rule(doc).tactic_technique_pairs() == [
        ("unmapped", "T1105"),
        ("command_and_control", "T1071.001"),
        ("defense_evasion", "T1218"),
        ("defense_evasion", "T1140"),
    ]
    assert compile_rule(dict(BASE, tags=["attack.t1003"])).tactic_technique_pairs() == [("unmapped", "T1003")]


def test_consecutive_tactics_share_following_techniques():
    doc = dict(BASE, tags=["attack.persistence", "attack.execution", "attack.t1053.005"])
    assert compile_rule(doc).tactic_technique_pairs() == [
        ("persistence", "T1053.005"),
        ("execution", "T1053.005"),
    ]
