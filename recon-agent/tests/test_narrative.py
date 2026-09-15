from recon_agent.narrative import NarrativeWriter


def _report_dict(findings):
    return {"target": "example.com", "overall_severity": "high" if findings else "info", "findings": findings}


def test_offline_narrative_with_no_findings():
    writer = NarrativeWriter(api_key=None)
    assert writer.is_live is False
    text = writer.write(_report_dict([]))
    assert "No notable findings" in text


def test_offline_narrative_highlights_worst_finding():
    findings = [
        {"category": "http-header", "title": "Missing HSTS header", "severity": "high", "detail": "no HSTS"},
        {"category": "tls", "title": "TLS certificate has expired", "severity": "critical", "detail": "expired 10 days ago"},
    ]
    writer = NarrativeWriter(api_key=None)
    text = writer.write(_report_dict(findings))
    assert "TLS certificate has expired" in text


def test_live_narrative_uses_llm_response(monkeypatch):
    class FakeTextBlock:
        type = "text"
        text = "Executive summary from the model."

    class FakeResponse:
        content = [FakeTextBlock()]

    class FakeClient:
        @property
        def messages(self):
            return self

        def create(self, **kwargs):
            return FakeResponse()

    writer = NarrativeWriter(api_key=None)
    writer._client = FakeClient()
    assert writer.is_live is True
    text = writer.write(_report_dict([]))
    assert text == "Executive summary from the model."


def test_live_narrative_falls_back_on_exception():
    class FailingClient:
        @property
        def messages(self):
            return self

        def create(self, **kwargs):
            raise RuntimeError("boom")

    writer = NarrativeWriter(api_key=None)
    writer._client = FailingClient()
    text = writer.write(_report_dict([]))
    assert "offline heuristic summary" in text
    assert "LLM call failed" in text
