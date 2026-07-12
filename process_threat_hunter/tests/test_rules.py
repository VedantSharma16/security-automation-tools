from pathlib import Path

import pytest

from hunter.rules import RuleValidationError, load_rules

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"


def test_default_rules_load_and_are_unique():
    rules = load_rules(DEFAULT_RULES_PATH)
    assert len(rules) > 0
    assert len({r.id for r in rules}) == len(rules)


def test_default_rules_have_valid_severities():
    rules = load_rules(DEFAULT_RULES_PATH)
    for rule in rules:
        assert rule.severity in {"low", "medium", "high", "critical"}


def test_rejects_missing_keys(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("- id: incomplete\n  pattern: 'x'\n")
    with pytest.raises(RuleValidationError, match="missing required keys"):
        load_rules(bad)


def test_rejects_invalid_severity(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "- id: r1\n"
        "  pattern: 'x'\n"
        "  match_fields: [name]\n"
        "  severity: catastrophic\n"
        "  mitre_tactic: t\n"
        "  mitre_technique: T0000\n"
    )
    with pytest.raises(RuleValidationError, match="invalid severity"):
        load_rules(bad)


def test_rejects_invalid_match_field(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "- id: r1\n"
        "  pattern: 'x'\n"
        "  match_fields: [nickname]\n"
        "  severity: low\n"
        "  mitre_tactic: t\n"
        "  mitre_technique: T0000\n"
    )
    with pytest.raises(RuleValidationError, match="invalid match_fields"):
        load_rules(bad)


def test_rejects_invalid_regex(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "- id: r1\n"
        "  pattern: '[unclosed'\n"
        "  match_fields: [name]\n"
        "  severity: low\n"
        "  mitre_tactic: t\n"
        "  mitre_technique: T0000\n"
    )
    with pytest.raises(RuleValidationError, match="invalid regex"):
        load_rules(bad)


def test_rejects_duplicate_ids(tmp_path):
    bad = tmp_path / "bad.yaml"
    rule = (
        "- id: dup\n"
        "  pattern: 'x'\n"
        "  match_fields: [name]\n"
        "  severity: low\n"
        "  mitre_tactic: t\n"
        "  mitre_technique: T0000\n"
    )
    bad.write_text(rule + rule)
    with pytest.raises(RuleValidationError, match="duplicate rule ids"):
        load_rules(bad)


def test_rule_matches_name_case_insensitively(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- id: nc-shell\n"
        "  pattern: 'netcat'\n"
        "  match_fields: [name]\n"
        "  severity: high\n"
        "  mitre_tactic: t\n"
        "  mitre_technique: T0000\n"
    )
    rules = load_rules(rules_file)
    (rule,) = rules

    class FakeProcess:
        name = "NetCat.exe"
        exe = ""
        cmdline = []

    match = rule.matches(FakeProcess())
    assert match == ("name", "NetCat")


def test_rule_no_match_returns_none(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- id: nc-shell\n"
        "  pattern: 'netcat'\n"
        "  match_fields: [name]\n"
        "  severity: high\n"
        "  mitre_tactic: t\n"
        "  mitre_technique: T0000\n"
    )
    (rule,) = load_rules(rules_file)

    class FakeProcess:
        name = "explorer.exe"
        exe = ""
        cmdline = []

    assert rule.matches(FakeProcess()) is None
