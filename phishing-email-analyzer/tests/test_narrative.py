import json

from helpers import FIXTURES

from phishscope.checks import AnalysisConfig
from phishscope.narrative import TemplateSummarizer, build_llm_payload, get_summarizer
from phishscope.parser import parse_file
from phishscope.report import analyze


def test_template_summary_names_tactics():
    r = analyze(parse_file(FIXTURES / "bec_wire_fraud.eml"), AnalysisConfig(["acme-corp.com"]))
    text = TemplateSummarizer().summarize(r)
    assert "malicious" in text
    assert "sender impersonation" in text and "BEC" in text


def test_template_summary_clean():
    r = analyze(parse_file(FIXTURES / "legit_newsletter.eml"))
    assert "No phishing indicators" in TemplateSummarizer().summarize(r)


def test_llm_payload_excludes_raw_body_and_hidden_injection_text():
    """The credential-phish fixture hides 'Ignore all previous instructions' in
    white 1px text and an HTML comment. The LLM must never be shown it."""
    r = analyze(parse_file(FIXTURES / "credential_phish.eml"))
    payload = build_llm_payload(r)
    assert payload.startswith("<untrusted_evidence>") and payload.endswith("</untrusted_evidence>")
    assert "ignore" not in payload.lower()
    assert "<form" not in payload
    inner = payload.removeprefix("<untrusted_evidence>").removesuffix("</untrusted_evidence>")
    assert json.loads(inner)["verdict"] == "malicious"


def test_llm_falls_back_without_api_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(True), TemplateSummarizer)
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_no_llm_requested():
    assert isinstance(get_summarizer(False), TemplateSummarizer)


def test_anthropic_summarizer_sends_only_structured_payload():
    """Exercise the Claude path with a fake client: no network, no SDK needed."""
    from types import SimpleNamespace

    from phishscope.narrative import SYSTEM_PROMPT, AnthropicSummarizer

    calls = {}

    class FakeMessages:
        def create(self, **kwargs):
            calls.update(kwargs)
            return SimpleNamespace(content=[SimpleNamespace(type="text", text="summary")])

    s = AnthropicSummarizer.__new__(AnthropicSummarizer)
    s._client = SimpleNamespace(messages=FakeMessages())
    s._model = "test-model"

    r = analyze(parse_file(FIXTURES / "credential_phish.eml"))
    assert s.summarize(r) == "summary"
    assert calls["system"] == SYSTEM_PROMPT
    assert calls["messages"][0]["content"] == build_llm_payload(r)
