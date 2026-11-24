import json

import pytest

from prompt_firewall.rules import RuleValidationError, load_rules


def _write(tmp_path, rules, weights=None):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({
        "severity_weights": weights or {"low": 1, "medium": 2, "high": 3, "critical": 4},
        "rules": rules,
    }))
    return path


def _rule(**overrides):
    base = {"id": "X-1", "name": "x", "category": "c", "severity": "high", "patterns": ["foo"]}
    base.update(overrides)
    return base


def test_default_pack_loads_and_ids_unique():
    pack = load_rules()
    ids = [r.id for r in pack.rules]
    assert len(ids) == len(set(ids)) >= 10
    assert all(r.owasp and r.atlas for r in pack.rules)


def test_bad_regex_fails_loudly(tmp_path):
    with pytest.raises(RuleValidationError, match="bad regex"):
        load_rules(_write(tmp_path, [_rule(patterns=["(unclosed"])]))


def test_invalid_severity(tmp_path):
    with pytest.raises(RuleValidationError, match="invalid severity"):
        load_rules(_write(tmp_path, [_rule(severity="spicy")]))


def test_duplicate_ids(tmp_path):
    with pytest.raises(RuleValidationError, match="duplicate"):
        load_rules(_write(tmp_path, [_rule(), _rule()]))


def test_missing_weights(tmp_path):
    with pytest.raises(RuleValidationError, match="severity_weights"):
        load_rules(_write(tmp_path, [_rule()], weights={"low": 1}))


def test_patterns_are_case_insensitive(tmp_path):
    pack = load_rules(_write(tmp_path, [_rule(patterns=["ignore"])]))
    assert pack.rules[0].search("IGNORE me")
