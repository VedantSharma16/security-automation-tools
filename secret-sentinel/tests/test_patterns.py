from pathlib import Path

import pytest

from secret_sentinel.patterns import load_signatures

DEFAULT_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_patterns.yaml"


def test_default_patterns_load_successfully():
    signatures = load_signatures(DEFAULT_PATTERNS_PATH)
    assert len(signatures) >= 10
    ids = {sig.id for sig in signatures}
    assert "aws-access-key-id" in ids
    assert "private-key-block" in ids


def test_default_patterns_have_unique_ids():
    signatures = load_signatures(DEFAULT_PATTERNS_PATH)
    ids = [sig.id for sig in signatures]
    assert len(ids) == len(set(ids))


def test_load_signatures_rejects_duplicate_ids(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(
        """
- id: dup
  pattern: 'foo'
  severity: low
  category: test
  confidence: high
  description: first
- id: dup
  pattern: 'bar'
  severity: low
  category: test
  confidence: high
  description: second
"""
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_signatures(bad_yaml)


def test_load_signatures_rejects_missing_field(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(
        """
- id: incomplete
  pattern: 'foo'
  severity: low
"""
    )
    with pytest.raises(ValueError, match="missing fields"):
        load_signatures(bad_yaml)


def test_load_signatures_rejects_invalid_severity(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(
        """
- id: bad-severity
  pattern: 'foo'
  severity: catastrophic
  category: test
  confidence: high
  description: bad
"""
    )
    with pytest.raises(ValueError, match="invalid severity"):
        load_signatures(bad_yaml)


def test_load_signatures_empty_file_returns_empty_list(tmp_path):
    empty_yaml = tmp_path / "empty.yaml"
    empty_yaml.write_text("")
    assert load_signatures(empty_yaml) == []
