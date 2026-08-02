from secretscan.scanner import Finding
from secretscan.triage import Triager, triage_findings


def _finding(detector, file_path, rule_id="generic-high-entropy-secret"):
    return Finding(
        rule_id=rule_id,
        severity="low" if detector == "entropy" else "high",
        category="generic",
        description="test finding",
        detector=detector,
        file_path=file_path,
        line_number=1,
        preview="Tg5k****yF4d",
        fingerprint=f"fp-{detector}-{file_path}",
    )


def test_rule_based_findings_get_likely_secret_without_llm_call():
    triager = Triager(use_llm=False)
    result = triager.triage(_finding("rule", "app.py", rule_id="aws-access-key-id"))
    assert result.verdict == "likely_secret"
    assert result.source == "offline"


def test_entropy_finding_in_test_path_flagged_as_false_positive_offline():
    triager = Triager(use_llm=False)
    result = triager.triage(_finding("entropy", "tests/fixtures/sample.py"))
    assert result.verdict == "likely_false_positive"
    assert result.source == "offline"


def test_entropy_finding_in_source_path_is_uncertain_offline():
    triager = Triager(use_llm=False)
    result = triager.triage(_finding("entropy", "app/config.py"))
    assert result.verdict == "uncertain"
    assert result.source == "offline"


def test_triager_without_api_key_is_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    triager = Triager(use_llm=True)
    assert triager.is_live is False


def test_triage_findings_returns_one_result_per_fingerprint():
    findings = [_finding("rule", "a.py"), _finding("entropy", "b.py")]
    results = triage_findings(findings, use_llm=False)
    assert set(results) == {f.fingerprint for f in findings}
    assert all(r.verdict in ("likely_secret", "likely_false_positive", "uncertain") for r in results.values())
