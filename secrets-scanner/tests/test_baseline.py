import json

from secretscan.baseline import apply_baseline, load_baseline, save_baseline
from secretscan.scanner import Finding


def _finding(fingerprint="fp1"):
    return Finding(
        rule_id="aws-access-key-id",
        severity="critical",
        category="cloud",
        description="AWS Access Key ID",
        detector="rule",
        file_path="app.py",
        line_number=3,
        preview="AKIA****MNOP",
        fingerprint=fingerprint,
    )


def test_load_baseline_missing_file_returns_empty_set(tmp_path):
    assert load_baseline(tmp_path / "does-not-exist.json") == set()


def test_save_and_load_baseline_round_trip(tmp_path):
    path = tmp_path / "baseline.json"
    findings = [_finding("fp1"), _finding("fp2")]

    save_baseline(findings, path)
    loaded = load_baseline(path)

    assert loaded == {"fp1", "fp2"}


def test_save_baseline_never_stores_preview_text(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline([_finding("fp1")], path)

    data = json.loads(path.read_text())
    assert data == {"ignored_fingerprints": ["fp1"]}
    assert "AKIA" not in path.read_text()


def test_apply_baseline_filters_known_fingerprints():
    findings = [_finding("fp1"), _finding("fp2")]
    remaining = apply_baseline(findings, {"fp1"})

    assert len(remaining) == 1
    assert remaining[0].fingerprint == "fp2"


def test_apply_baseline_empty_set_keeps_everything():
    findings = [_finding("fp1"), _finding("fp2")]
    assert apply_baseline(findings, set()) == findings
