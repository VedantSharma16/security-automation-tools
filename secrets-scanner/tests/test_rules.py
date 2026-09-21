import pytest

from secretscan.rules import RuleValidationError, load_rules


def test_default_rules_load_and_are_all_unique():
    rules = load_rules()
    assert len(rules) > 10
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_signature_rule_matches_without_needing_entropy(tmp_path):
    rules = {r.id: r for r in load_rules()}
    rule = rules["aws-access-key-id"]
    matches = rule.find_all("key = 'AKIAIOSFODNN7EXAMPLE'")
    assert len(matches) == 1
    assert matches[0].secret_text == "AKIAIOSFODNN7EXAMPLE"


def test_entropy_gated_rule_rejects_placeholder_value():
    rules = {r.id: r for r in load_rules()}
    rule = rules["generic-secret-assignment"]
    assert rule.find_all('api_key = "changeme_changeme_1234"') == []


def test_entropy_gated_rule_accepts_random_value():
    rules = {r.id: r for r in load_rules()}
    rule = rules["generic-secret-assignment"]
    matches = rule.find_all('api_key = "zQ9kLp2XwR8vT4mN6bY1cF7hJ3sD5aE0"')
    assert len(matches) == 1
    assert matches[0].secret_text == "zQ9kLp2XwR8vT4mN6bY1cF7hJ3sD5aE0"


def test_entropy_gated_rule_matches_keyword_embedded_in_identifier():
    rules = {r.id: r for r in load_rules()}
    rule = rules["generic-secret-assignment"]
    matches = rule.find_all('SECRET_TOKEN = "zQ9kLp2XwR8vT4mN6bY1cF7hJ3sD5aE0"')
    assert len(matches) == 1


def _write_rules(tmp_path, yaml_text):
    path = tmp_path / "rules.yaml"
    path.write_text(yaml_text)
    return path


def test_load_rules_rejects_missing_required_keys(tmp_path):
    path = _write_rules(tmp_path, "- id: broken\n  pattern: 'x'\n")
    with pytest.raises(RuleValidationError, match="missing required keys"):
        load_rules(path)


def test_load_rules_rejects_invalid_severity(tmp_path):
    path = _write_rules(
        tmp_path,
        "- id: broken\n  pattern: 'x'\n  severity: apocalyptic\n  category: c\n",
    )
    with pytest.raises(RuleValidationError, match="invalid severity"):
        load_rules(path)


def test_load_rules_rejects_bad_regex(tmp_path):
    path = _write_rules(
        tmp_path,
        "- id: broken\n  pattern: '('\n  severity: low\n  category: c\n",
    )
    with pytest.raises(RuleValidationError, match="invalid regex"):
        load_rules(path)


def test_load_rules_rejects_duplicate_ids(tmp_path):
    path = _write_rules(
        tmp_path,
        "- id: dup\n  pattern: 'x'\n  severity: low\n  category: c\n"
        "- id: dup\n  pattern: 'y'\n  severity: low\n  category: c\n",
    )
    with pytest.raises(RuleValidationError, match="duplicate rule ids"):
        load_rules(path)


def test_load_rules_rejects_non_list_file(tmp_path):
    path = _write_rules(tmp_path, "not_a_list: true\n")
    with pytest.raises(RuleValidationError, match="YAML list"):
        load_rules(path)
