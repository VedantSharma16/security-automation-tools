from phish_forensics.narrative import NarrativeWriter

REPORT_WITH_FINDINGS = {
    "message": {"subject": "Urgent!", "from_display_name": "PayPal Security", "from_addr": "x@evil.com"},
    "summary": {"highest_severity": "CRITICAL", "risk_score": 95, "total_findings": 2},
    "findings": [
        {"severity": "CRITICAL", "title": "Display name spoof", "detail": "Impersonates PayPal."},
        {"severity": "HIGH", "title": "Auth failure", "detail": "DMARC failed."},
    ],
}

REPORT_NO_FINDINGS = {
    "message": {"subject": "Hi", "from_display_name": "A Friend", "from_addr": "a@example.com"},
    "summary": {"highest_severity": None, "risk_score": 0, "total_findings": 0},
    "findings": [],
}


def test_offline_by_default_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    writer = NarrativeWriter()
    assert writer.is_live is False


def test_offline_narrative_mentions_worst_finding(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    writer = NarrativeWriter()
    text = writer.write(REPORT_WITH_FINDINGS)
    assert "offline heuristic summary" in text
    assert "Display name spoof" in text


def test_offline_narrative_handles_no_findings(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    writer = NarrativeWriter()
    text = writer.write(REPORT_NO_FINDINGS)
    assert "No phishing indicators detected" in text


def test_explicit_api_key_falls_back_gracefully_on_bad_key():
    # A syntactically-present but invalid key must never crash the tool —
    # either the SDK isn't installed (offline fallback) or the API call
    # fails and we fall back to the same offline text with an error note.
    writer = NarrativeWriter(api_key="not-a-real-key")
    if writer.is_live:
        # anthropic SDK happens to be installed: the call itself should fail
        # cleanly (bad key / no network) and fall back to the offline text.
        text = writer.write(REPORT_NO_FINDINGS)
        assert "No phishing indicators detected" in text or "LLM call failed" in text
    else:
        assert writer.write(REPORT_NO_FINDINGS).startswith("[offline heuristic summary")
