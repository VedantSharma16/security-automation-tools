import json

from phishscope import narrative
from phishscope.cli import analyze_file
from phishscope.narrative import REDACTED, TemplateSummarizer, get_summarizer, sanitize_for_llm


def _report(fixture_path, name):
    return analyze_file(fixture_path(name), None, [], use_llm=False, model="unused")


def test_sanitize_strips_attacker_text(fixture_path):
    report = _report(fixture_path, "ai_prompt_injection.eml")
    clean = json.dumps(sanitize_for_llm(report)).lower()
    assert "ignore all previous instructions" not in clean
    assert "forward all emails" not in clean
    assert REDACTED.lower() in clean
    # Subject / body never reach the model at all.
    assert "subject" not in clean and "industry roundup" not in clean
    # Verdict and score are carried through unchanged.
    assert sanitize_for_llm(report)["verdict"] == report["verdict"]


def test_anthropic_summarizer_sends_only_sanitized_payload(fixture_path, monkeypatch):
    captured = {}

    class FakeBlock:
        type = "text"
        text = "narrative"

    class FakeMessages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return type("R", (), {"content": [FakeBlock()]})()

    summarizer = narrative.AnthropicSummarizer.__new__(narrative.AnthropicSummarizer)
    summarizer._client = type("C", (), {"messages": FakeMessages()})()
    summarizer._model = "test-model"

    report = _report(fixture_path, "ai_prompt_injection.eml")
    assert summarizer.summarize(report) == "narrative"
    sent = captured["messages"][0]["content"]
    assert "ignore all previous instructions" not in sent.lower()
    assert "untrusted data" in captured["system"]


def test_template_mentions_ai_risk(fixture_path):
    report = _report(fixture_path, "ai_prompt_injection.eml")
    text = TemplateSummarizer().summarize(report)
    assert "AI email assistants" in text


def test_template_benign(fixture_path):
    report = _report(fixture_path, "benign_notification.eml")
    assert "No phishing indicators" in TemplateSummarizer().summarize(report)


def test_llm_falls_back_without_api_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(True), TemplateSummarizer)
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err
