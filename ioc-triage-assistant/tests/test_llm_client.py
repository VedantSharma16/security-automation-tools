from ioc_triage.llm_client import LLMClient, TriageContext, build_prompt


def _sample_context(severity="high"):
    return TriageContext(
        alert_text="Beacon traffic observed to a known malicious IP.",
        indicators=[{"value": "185.220.101.1", "category": "ipv4"}],
        enrichment=[
            {
                "value": "185.220.101.1",
                "category": "ipv4",
                "is_known_malicious": True,
                "confidence": "high",
                "source": "demo-feed",
                "notes": "Known Tor exit node.",
            }
        ],
        matched_techniques=[
            ({"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
              "text": "..."}, 0.42)
        ],
        severity=severity,
    )


def test_llm_client_without_api_key_is_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = LLMClient(api_key=None)
    assert client.is_live is False


def test_offline_summary_mentions_flagged_indicator_and_severity():
    client = LLMClient(api_key=None)
    summary = client.summarize(_sample_context(severity="critical"))
    assert "offline heuristic summary" in summary
    assert "CRITICAL" in summary
    assert "185.220.101.1" in summary
    assert "T1071" in summary


def test_offline_summary_handles_no_hits():
    context = TriageContext(
        alert_text="Routine login from a known corporate IP.",
        indicators=[],
        enrichment=[],
        matched_techniques=[],
        severity="low",
    )
    summary = LLMClient(api_key=None).summarize(context)
    assert "LOW" in summary
    assert "No indicators matched" in summary


def test_build_prompt_includes_all_sections():
    prompt = build_prompt(_sample_context())
    assert "## Alert" in prompt
    assert "## Extracted indicators" in prompt
    assert "## Threat-intel enrichment" in prompt
    assert "## Retrieved ATT&CK context (RAG)" in prompt
    assert "185.220.101.1" in prompt
