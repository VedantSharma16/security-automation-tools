import json

from secretscan.baseline import apply_baseline, load_baseline, save_baseline
from secretscan.finding import Finding


def _finding(fingerprint="abc123"):
    return Finding(
        rule_id="test-rule",
        severity="high",
        category="generic-secret",
        description="d",
        file_path="f.py",
        redacted="ab...cd",
        fingerprint=fingerprint,
        source="working-tree",
    )


def test_load_baseline_missing_file_returns_empty_set(tmp_path):
    assert load_baseline(tmp_path / "nope.json") == set()


def test_save_and_load_baseline_round_trip(tmp_path):
    path = tmp_path / "baseline.json"
    findings = [_finding("aaa"), _finding("bbb")]
    save_baseline(findings, path)

    loaded = load_baseline(path)
    assert loaded == {"aaa", "bbb"}

    data = json.loads(path.read_text())
    assert data["finding_count"] == 2


def test_apply_baseline_filters_matching_fingerprints():
    findings = [_finding("aaa"), _finding("bbb")]
    remaining = apply_baseline(findings, {"aaa"})
    assert [f.fingerprint for f in remaining] == ["bbb"]


def test_apply_baseline_with_empty_baseline_keeps_everything():
    findings = [_finding("aaa")]
    assert apply_baseline(findings, set()) == findings
