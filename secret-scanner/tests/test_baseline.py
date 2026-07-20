from secretscanner import baseline
from secretscanner.rules import load_default_rules
from secretscanner.scanner import scan_path
from sample_secrets import AWS_ACCESS_KEY_ID, GITHUB_TOKEN


def test_save_and_load_baseline_round_trips(tmp_path):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    findings, _ = scan_path(tmp_path, load_default_rules())
    baseline_path = tmp_path / "baseline.json"

    baseline.save_baseline(findings, baseline_path)
    loaded = baseline.load_baseline(baseline_path)

    assert loaded == {findings[0].fingerprint()}


def test_filter_new_suppresses_known_findings(tmp_path):
    (tmp_path / "config.py").write_text(
        f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n'
        f'GITHUB_TOKEN = "{GITHUB_TOKEN}"\n'
    )
    findings, _ = scan_path(tmp_path, load_default_rules())
    assert len(findings) == 2

    known = {findings[0].fingerprint()}
    remaining = baseline.filter_new(findings, known)

    assert len(remaining) == 1
    assert remaining[0].fingerprint() != findings[0].fingerprint()


def test_filter_new_returns_all_findings_for_empty_baseline(tmp_path):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    findings, _ = scan_path(tmp_path, load_default_rules())

    remaining = baseline.filter_new(findings, set())

    assert remaining == findings


def test_new_finding_after_baseline_is_not_suppressed(tmp_path):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    findings, _ = scan_path(tmp_path, load_default_rules())
    baseline_path = tmp_path / "baseline.json"
    baseline.save_baseline(findings, baseline_path)

    (tmp_path / "new_config.py").write_text(
        f'GITHUB_TOKEN = "{GITHUB_TOKEN}"\n'
    )
    all_findings, _ = scan_path(tmp_path, load_default_rules())
    known = baseline.load_baseline(baseline_path)
    remaining = baseline.filter_new(all_findings, known)

    assert len(remaining) == 1
    assert remaining[0].file == "new_config.py"
