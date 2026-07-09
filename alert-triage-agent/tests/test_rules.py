import pytest

from triage_agent.models import Severity
from triage_agent.parser import parse_lines
from triage_agent.rules import RuleEngine, RuleLoadError, load_rules


def write_rules(tmp_path, yaml_text):
    p = tmp_path / "rules.yaml"
    p.write_text(yaml_text)
    return p


def test_default_rules_load_without_error():
    rules = load_rules()
    assert len(rules) > 0
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"


def test_load_rules_rejects_duplicate_ids(tmp_path):
    p = write_rules(
        tmp_path,
        """
rules:
  - id: DUP-1
    pattern: 'foo'
    severity: low
    mitre_technique: T0000
  - id: DUP-1
    pattern: 'bar'
    severity: low
    mitre_technique: T0000
""",
    )
    with pytest.raises(RuleLoadError):
        load_rules(p)


def test_load_rules_rejects_bad_regex(tmp_path):
    p = write_rules(
        tmp_path,
        """
rules:
  - id: BAD-1
    pattern: '['
    severity: low
    mitre_technique: T0000
""",
    )
    with pytest.raises(RuleLoadError):
        load_rules(p)


def test_load_rules_rejects_missing_top_level_key(tmp_path):
    p = write_rules(tmp_path, "not_rules: []")
    with pytest.raises(RuleLoadError):
        load_rules(p)


def test_load_rules_rejects_invalid_severity(tmp_path):
    p = write_rules(
        tmp_path,
        """
rules:
  - id: SEV-1
    pattern: 'foo'
    severity: extreme
    mitre_technique: T0000
""",
    )
    with pytest.raises(RuleLoadError):
        load_rules(p)


def test_rule_engine_matches_pattern(tmp_path):
    p = write_rules(
        tmp_path,
        """
rules:
  - id: PW-1
    name: Failed login
    pattern: 'Failed password'
    severity: medium
    mitre_technique: T1110
""",
    )
    engine = RuleEngine.from_file(p)
    events = parse_lines("Failed password for root\nnothing interesting here\n")
    findings = engine.scan(events)

    assert len(findings) == 1
    assert findings[0].rule.id == "PW-1"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].event.line_number == 1


def test_rule_engine_is_case_insensitive(tmp_path):
    p = write_rules(
        tmp_path,
        """
rules:
  - id: CI-1
    pattern: 'mimikatz'
    severity: critical
    mitre_technique: T1003
""",
    )
    engine = RuleEngine.from_file(p)
    events = parse_lines("Running MIMIKATZ.EXE now")
    findings = engine.scan(events)
    assert len(findings) == 1


def test_rule_engine_one_line_can_match_multiple_rules(tmp_path):
    p = write_rules(
        tmp_path,
        """
rules:
  - id: R1
    pattern: 'foo'
    severity: low
    mitre_technique: T0001
  - id: R2
    pattern: 'bar'
    severity: high
    mitre_technique: T0002
""",
    )
    engine = RuleEngine.from_file(p)
    events = parse_lines("foo and bar on the same line")
    findings = engine.scan(events)
    assert {f.rule.id for f in findings} == {"R1", "R2"}
