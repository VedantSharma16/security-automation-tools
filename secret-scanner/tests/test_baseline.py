from secret_fixtures import fake_aws_access_key_id
from secret_scanner.baseline import Baseline
from secret_scanner.scanner import Finding

AWS_KEY = fake_aws_access_key_id()


def _finding(secret=None, file_path="app.py", line_number=1):
    secret = secret if secret is not None else AWS_KEY
    return Finding(
        rule_id="aws-access-key-id",
        description="AWS Access Key ID",
        severity="critical",
        file_path=file_path,
        line_number=line_number,
        secret=secret,
        line_text=f'key = "{secret}"',
    )


def test_empty_baseline_filters_nothing():
    baseline = Baseline()
    findings = [_finding()]
    assert baseline.filter_findings(findings) == findings


def test_add_and_filter_suppresses_matching_fingerprint():
    finding = _finding()
    baseline = Baseline()
    baseline.add(finding, reason="test fixture")
    assert baseline.filter_findings([finding]) == []


def test_filter_only_suppresses_exact_fingerprint_matches():
    known = _finding(secret=AWS_KEY)
    unknown = _finding(secret=AWS_KEY[::-1])
    baseline = Baseline.from_findings([known])

    remaining = baseline.filter_findings([known, unknown])
    assert remaining == [unknown]


def test_baseline_suppression_survives_line_number_change():
    original = _finding(line_number=5)
    baseline = Baseline.from_findings([original])

    moved = _finding(line_number=42)
    assert baseline.filter_findings([moved]) == []


def test_save_and_load_round_trip(tmp_path):
    finding = _finding()
    baseline = Baseline.from_findings([finding], reason="known test fixture")
    path = tmp_path / "baseline.json"
    baseline.save(path)

    loaded = Baseline.load(path)
    assert len(loaded) == 1
    assert finding.fingerprint in loaded
    assert loaded.filter_findings([finding]) == []


def test_load_missing_file_returns_empty_baseline(tmp_path):
    loaded = Baseline.load(tmp_path / "does-not-exist.json")
    assert len(loaded) == 0
