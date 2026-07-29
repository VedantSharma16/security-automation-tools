import json

from secret_sentinel.baseline import apply_allowlist, load_allowlist, save_allowlist
from secret_sentinel.scanner import Finding


def _finding(fingerprint: str) -> Finding:
    return Finding(
        file="app.py",
        line_number=1,
        signature_id="aws-access-key-id",
        category="cloud-credential",
        severity="critical",
        confidence="high",
        description="AWS Access Key ID.",
        redacted_value="AKIA****EXAMPLE",
        entropy=3.9,
        fingerprint=fingerprint,
    )


def test_save_allowlist_writes_sorted_unique_fingerprints(tmp_path):
    path = tmp_path / "allowlist.json"
    findings = [_finding("bbb"), _finding("aaa"), _finding("aaa")]
    save_allowlist(findings, path)
    data = json.loads(path.read_text())
    assert data == {"fingerprints": ["aaa", "bbb"]}


def test_load_allowlist_round_trips(tmp_path):
    path = tmp_path / "allowlist.json"
    save_allowlist([_finding("fp1"), _finding("fp2")], path)
    loaded = load_allowlist(path)
    assert loaded == {"fp1", "fp2"}


def test_apply_allowlist_filters_matching_fingerprints():
    findings = [_finding("known"), _finding("unknown")]
    remaining = apply_allowlist(findings, {"known"})
    assert len(remaining) == 1
    assert remaining[0].fingerprint == "unknown"


def test_apply_allowlist_with_empty_allowlist_keeps_everything():
    findings = [_finding("a"), _finding("b")]
    assert apply_allowlist(findings, set()) == findings
