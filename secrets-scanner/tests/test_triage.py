from secretscanner.scanner import Finding
from secretscanner.triage import SecretTriageClient, triage_finding, triage_findings


def _finding(**overrides):
    defaults = dict(
        file="app/settings.py",
        line_number=10,
        pattern_name="AWS Access Key ID",
        category="cloud",
        severity="critical",
        detector="regex",
        redacted_value="AKIA************ERTY",
        remediation="Rotate it.",
        line_preview="AWS_KEY = 'AKIAZQTKPMNBVCXWERTY'",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_triage_flags_test_directory_as_likely_false_positive():
    f = _finding(file="tests/fixtures/sample.py")
    result = triage_finding(f)
    assert result.likely_false_positive is True
    assert any("test" in r for r in result.reasons)


def test_triage_flags_placeholder_value_as_likely_false_positive():
    f = _finding(line_preview="API_KEY = 'your_api_key_goes_here_1234567890'")
    result = triage_finding(f)
    assert result.likely_false_positive is True


def test_triage_flags_low_severity_entropy_only_match():
    f = _finding(detector="entropy", severity="low", pattern_name="High-entropy base64 string")
    result = triage_finding(f)
    assert result.likely_false_positive is True


def test_triage_does_not_flag_genuine_looking_finding():
    f = _finding(file="app/settings.py", line_preview="AWS_KEY = 'AKIAZQTKPMNBVCXWERTY'")
    result = triage_finding(f)
    assert result.likely_false_positive is False
    assert result.reasons == ()


def test_triage_findings_preserves_order_and_source():
    findings = [_finding(), _finding(file="tests/x.py")]
    results = triage_findings(findings, source="git-history")
    assert [r.source for r in results] == ["git-history", "git-history"]
    assert len(results) == 2


def test_client_defaults_to_offline_without_use_llm_flag():
    client = SecretTriageClient()
    assert client.is_live is False


def test_client_stays_offline_even_with_env_key_when_not_requested(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-not-used")
    client = SecretTriageClient(use_llm=False)
    assert client.is_live is False


def test_offline_narrative_flags_critical_findings():
    triaged = triage_findings([_finding(severity="critical")])
    client = SecretTriageClient()
    narrative = client.narrate(triaged, target="/repo")
    assert "CRITICAL" in narrative
    assert "AWS Access Key ID" in narrative


def test_offline_narrative_handles_no_findings():
    client = SecretTriageClient()
    narrative = client.narrate([], target="/repo")
    assert "0 finding" in narrative
