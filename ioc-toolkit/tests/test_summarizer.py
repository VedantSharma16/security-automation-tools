from ioc_toolkit.enrichment import enrich
from ioc_toolkit.extractor import extract
from ioc_toolkit.summarizer import HeuristicSummarizer, ClaudeSummarizer, TriageSummary, get_summarizer


def test_heuristic_summary_informational_on_clean_text():
    text = "Nothing to see here."
    summary = HeuristicSummarizer().summarize(text, extract(text), enrich(text))
    assert summary.severity == "informational"
    assert summary.score == 0


def test_heuristic_summary_escalates_with_hashes_and_attack_hits():
    text = (
        "Mimikatz dropped hash d41d8cd98f00b204e9800998ecf8427e "
        "and beaconed to 203.0.113.42 and evil-domain.io referencing CVE-2024-3094."
    )
    extraction = extract(text)
    hits = enrich(text)
    summary = HeuristicSummarizer().summarize(text, extraction, hits)
    assert summary.severity in {"medium", "high"}
    assert summary.score > 0
    assert any("CVE-2024-3094" in a or "hash" in a.lower() or "EDR" in a for a in summary.recommended_actions)


def test_get_summarizer_falls_back_to_heuristic_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(), HeuristicSummarizer)


class _FakeTextBlock:
    def __init__(self, text):
        self.text = text


class _FakeResponse:
    def __init__(self, text):
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, reply_text):
        self._reply_text = reply_text

    def create(self, **kwargs):
        return _FakeResponse(self._reply_text)


class _FakeAnthropicClient:
    def __init__(self, reply_text):
        self.messages = _FakeMessages(reply_text)


def test_claude_summarizer_parses_structured_reply():
    fake_reply = (
        "SEVERITY: high\n"
        "NARRATIVE: This report describes a credential dumping attack chain.\n"
        "ACTIONS:\n"
        "- Isolate the affected host\n"
        "- Rotate credentials\n"
    )
    client = _FakeAnthropicClient(fake_reply)
    summarizer = ClaudeSummarizer(client=client)

    text = "Mimikatz was used to dump lsass memory."
    result = summarizer.summarize(text, extract(text), enrich(text))

    assert isinstance(result, TriageSummary)
    assert result.severity == "high"
    assert "credential dumping" in result.narrative.lower()
    assert result.recommended_actions == [
        "Isolate the affected host",
        "Rotate credentials",
    ]
