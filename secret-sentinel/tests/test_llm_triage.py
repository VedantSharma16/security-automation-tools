import pytest

from secret_sentinel.llm_triage import LLMTriageClient, _parse_verdict, build_prompt, triage_findings
from secret_sentinel.scanner import Finding


def _finding(confidence: str, entropy: float, signature_id: str = "generic-high-entropy-string") -> Finding:
    return Finding(
        file="app.py",
        line_number=1,
        signature_id=signature_id,
        category="generic-secret",
        severity="medium",
        confidence=confidence,
        description="test finding",
        redacted_value="Xk29****4Rb",
        entropy=entropy,
        fingerprint=f"fp-{signature_id}-{entropy}",
    )


@pytest.fixture(autouse=True)
def no_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_client_without_api_key_is_not_live():
    client = LLMTriageClient()
    assert client.is_live is False


def test_offline_triage_high_confidence_is_true_positive():
    client = LLMTriageClient()
    verdict = client.triage(_finding(confidence="high", entropy=2.0, signature_id="aws-access-key-id"))
    assert verdict["verdict"] == "true_positive"


def test_offline_triage_very_high_entropy_is_likely_true_positive():
    client = LLMTriageClient()
    verdict = client.triage(_finding(confidence="low", entropy=4.5))
    assert verdict["verdict"] == "likely_true_positive"


def test_offline_triage_moderate_entropy_is_uncertain():
    client = LLMTriageClient()
    verdict = client.triage(_finding(confidence="low", entropy=3.8))
    assert verdict["verdict"] == "uncertain"


def test_offline_triage_low_entropy_is_likely_false_positive():
    client = LLMTriageClient()
    verdict = client.triage(_finding(confidence="low", entropy=1.5))
    assert verdict["verdict"] == "likely_false_positive"


def test_offline_triage_rationale_mentions_offline_heuristic():
    client = LLMTriageClient()
    verdict = client.triage(_finding(confidence="medium", entropy=3.0))
    assert "offline heuristic" in verdict["rationale"]


def test_triage_findings_skips_high_confidence_findings():
    findings = [
        _finding(confidence="high", entropy=2.0, signature_id="aws-access-key-id"),
        _finding(confidence="low", entropy=4.0),
    ]
    verdicts = triage_findings(findings, LLMTriageClient())
    assert len(verdicts) == 1
    assert findings[1].fingerprint in verdicts
    assert findings[0].fingerprint not in verdicts


def test_build_prompt_never_includes_raw_secret_only_metadata():
    finding = _finding(confidence="low", entropy=4.0)
    prompt = build_prompt(finding)
    assert finding.redacted_value in prompt
    assert finding.description in prompt
    # Only the redacted preview should appear -- there is no raw value on the
    # Finding object at all by this point, so there's nothing else to leak.


def test_parse_verdict_extracts_verdict_and_rationale():
    finding = _finding(confidence="low", entropy=4.0)
    text = "VERDICT: false_positive\nRATIONALE: this looks like a UUID, not a secret."
    parsed = _parse_verdict(text, finding)
    assert parsed["verdict"] == "false_positive"
    assert parsed["rationale"] == "this looks like a UUID, not a secret."
    assert parsed["fingerprint"] == finding.fingerprint


def test_parse_verdict_defaults_to_uncertain_on_malformed_response():
    finding = _finding(confidence="low", entropy=4.0)
    parsed = _parse_verdict("not the expected format at all", finding)
    assert parsed["verdict"] == "uncertain"
