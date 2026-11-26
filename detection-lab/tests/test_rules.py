import textwrap

import pytest

from detlab.matcher import RuleSyntaxError
from detlab.rules import lint_rule_data, load_rules, parse_rule_text, yaml_load

GOOD = textwrap.dedent(
    """
    title: Test rule
    id: 11111111-2222-3333-4444-555555555555
    status: test
    description: test
    logsource: {category: process_creation, product: windows}
    detection:
      selection:
        Image|endswith: '\\whoami.exe'
      filter:
        User: 'SYSTEM'
      condition: selection and not filter
    falsepositives: [admins]
    level: low
    tags: [attack.discovery, attack.t1033]
    """
)


def test_parse_and_match():
    rule = parse_rule_text(GOOD)
    assert rule.matches({"Image": "C:\\Windows\\System32\\whoami.exe", "User": "bob"})
    assert not rule.matches({"Image": "C:\\Windows\\System32\\whoami.exe", "User": "SYSTEM"})
    assert rule.techniques == ["T1033"] and rule.tactics == ["discovery"]
    assert rule.matched_selections({"Image": "x\\whoami.exe", "User": "SYSTEM"}) == ["selection", "filter"]


def test_condition_list_is_or():
    rule = parse_rule_text(
        "detection:\n  a: {F: x}\n  b: {F: y}\n  condition: [a, b]\n"
    )
    assert rule.matches({"F": "y"})


def test_clean_rule_has_no_lint_issues():
    assert lint_rule_data(yaml_load(GOOD)) == []


def lint_messages(text):
    return [str(i) for i in lint_rule_data(yaml_load(text))]


def test_lint_flags_metadata_problems():
    bad = GOOD.replace("11111111-2222-3333-4444-555555555555", "not-a-uuid").replace("level: low", "level: urgent")
    bad = bad.replace("attack.t1033", "attack.t33")
    msgs = lint_messages(bad)
    assert any("not a UUID" in m for m in msgs)
    assert any("level 'urgent'" in m for m in msgs)
    assert any("malformed ATT&CK tag 'attack.t33'" in m for m in msgs)


def test_lint_warns_on_unused_selection_and_missing_tags():
    text = GOOD.replace("condition: selection and not filter", "condition: selection").replace(
        "tags: [attack.discovery, attack.t1033]", "tags: []"
    )
    msgs = lint_messages(text)
    assert any("'filter' is never used" in m for m in msgs)
    assert any("no ATT&CK technique tag" in m for m in msgs)


def test_lint_reports_compile_errors():
    text = GOOD.replace("condition: selection and not filter", "condition: selection and nope")
    msgs = lint_messages(text)
    assert msgs == ["ERROR: condition references undefined selection 'nope'"]


def test_duplicate_yaml_keys_are_rejected():
    dup = "detection:\n  sel:\n    CommandLine|contains: a\n    CommandLine|contains: b\n  condition: sel\n"
    with pytest.raises(RuleSyntaxError, match="duplicate key"):
        parse_rule_text(dup)


@pytest.mark.parametrize(
    "text",
    [
        "just a string",
        "title: x\n",
        "detection: {sel: {F: x}}\n",
        "detection: {condition: sel}\n",
        "detection: {sel: {F: x}, condition: sel, timeframe: 5m}\n",
    ],
)
def test_structural_errors(text):
    with pytest.raises(RuleSyntaxError):
        parse_rule_text(text)


def test_load_rules_collects_errors_without_aborting(tmp_path):
    (tmp_path / "good.yml").write_text(GOOD)
    (tmp_path / "bad.yml").write_text("detection: {condition: sel}\n")
    (tmp_path / "multi.yaml").write_text(GOOD + "\n---\n" + GOOD.replace("Test rule", "Second"))
    (tmp_path / "notes.txt").write_text("ignored")
    result = load_rules([tmp_path])
    assert sorted(r.title for r in result.rules) == ["Second", "Test rule", "Test rule"]
    assert list(result.errors) == [str(tmp_path / "bad.yml")]


def test_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        load_rules(["/nonexistent/rules"])
