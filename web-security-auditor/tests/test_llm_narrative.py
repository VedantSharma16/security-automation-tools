from webauditor.llm_narrative import NarrativeClient, build_prompt


def _summary():
    return {"risk_score": 65, "risk_rating": "high", "total_findings": 2}


def _findings():
    return [
        {
            "severity": "CRITICAL",
            "title": "Exposed .git directory",
            "owasp_category": "A05:2021 Security Misconfiguration",
            "description": "Full source history is retrievable.",
        },
        {
            "severity": "LOW",
            "title": "Missing Referrer-Policy header",
            "owasp_category": "A05:2021 Security Misconfiguration",
            "description": "Referrer leakage risk.",
        },
    ]


def test_offline_client_has_no_live_backend_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = NarrativeClient()
    assert client.is_live is False


def test_offline_summary_mentions_rating_and_top_finding(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = NarrativeClient()
    narrative = client.summarize("https://example.com", _findings(), _summary())
    assert "HIGH" in narrative
    assert "Exposed .git directory" in narrative
    assert "offline heuristic summary" in narrative


def test_offline_summary_handles_no_findings(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = NarrativeClient()
    narrative = client.summarize("https://example.com", [], {"risk_score": 0, "risk_rating": "none", "total_findings": 0})
    assert "No findings recorded" in narrative


def test_build_prompt_includes_target_and_findings():
    prompt = build_prompt("https://example.com", _findings(), _summary())
    assert "https://example.com" in prompt
    assert "Exposed .git directory" in prompt
    assert "risk score 65" in prompt.lower() or "65" in prompt
