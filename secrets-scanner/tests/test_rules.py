import pytest

from secretscan.rules import RuleValidationError, load_rules


def test_load_default_rules(default_rules_path):
    rules = load_rules(default_rules_path)
    assert len(rules) >= 15
    ids = [r.id for r in rules]
    assert "aws-access-key-id" in ids
    assert "github-pat" in ids
    assert "private-key-block" in ids


def test_aws_access_key_rule_matches(default_rules_path):
    rules = load_rules(default_rules_path)
    rule = next(r for r in rules if r.id == "aws-access-key-id")
    match = rule.search('aws_key = "AKIAABCDEFGHIJKLMNOP"')
    assert match is not None
    assert match.group(0) == "AKIAABCDEFGHIJKLMNOP"


def test_github_pat_rule_does_not_match_unrelated_text(default_rules_path):
    rules = load_rules(default_rules_path)
    rule = next(r for r in rules if r.id == "github-pat")
    assert rule.search("this is just a normal comment") is None


def test_load_rules_missing_required_key(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("- id: bad-rule\n  pattern: 'x'\n  severity: high\n")
    with pytest.raises(RuleValidationError, match="missing required keys"):
        load_rules(path)


def test_load_rules_invalid_severity(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("- id: bad-rule\n  pattern: 'x'\n  severity: extreme\n  category: generic\n")
    with pytest.raises(RuleValidationError, match="invalid severity"):
        load_rules(path)


def test_load_rules_invalid_regex(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("- id: bad-rule\n  pattern: '['\n  severity: high\n  category: generic\n")
    with pytest.raises(RuleValidationError, match="invalid regex"):
        load_rules(path)


def test_load_rules_duplicate_ids(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "- id: dup\n  pattern: 'a'\n  severity: low\n  category: generic\n"
        "- id: dup\n  pattern: 'b'\n  severity: low\n  category: generic\n"
    )
    with pytest.raises(RuleValidationError, match="duplicate rule ids"):
        load_rules(path)


def test_load_rules_not_a_list(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("just: a mapping\n")
    with pytest.raises(RuleValidationError, match="must contain a YAML list"):
        load_rules(path)
