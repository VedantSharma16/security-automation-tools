import json
import sys
import types

from secretscan.finding import Finding
from secretscan.llm_triage import (
    TRIAGE_CATEGORY,
    AnthropicTriager,
    OfflineHeuristicTriager,
    get_triager,
)


def _generic_finding(context_key):
    return Finding(
        rule_id="generic-secret-assignment",
        severity="medium",
        category=TRIAGE_CATEGORY,
        description="d",
        file_path="f.py",
        redacted="zQ9k...5aE0",
        fingerprint="fp",
        source="working-tree",
        context_key=context_key,
    )


def _signature_finding():
    return Finding(
        rule_id="aws-access-key-id",
        severity="critical",
        category="cloud-credential",
        description="d",
        file_path="f.py",
        redacted="AKIA...MPLE",
        fingerprint="fp2",
        source="working-tree",
        confidence="high",
        triage_reason="signature match",
    )


def test_offline_triager_leaves_signature_findings_untouched():
    finding = _signature_finding()
    OfflineHeuristicTriager().triage([finding])
    assert finding.confidence == "high"
    assert finding.triage_reason == "signature match"


def test_offline_triager_flags_id_like_names_as_low_confidence():
    finding = _generic_finding("request_id")
    OfflineHeuristicTriager().triage([finding])
    assert finding.confidence == "low"


def test_offline_triager_flags_secret_like_names_as_high_confidence():
    finding = _generic_finding("client_secret")
    OfflineHeuristicTriager().triage([finding])
    assert finding.confidence == "high"


def test_offline_triager_defaults_to_medium_confidence():
    finding = _generic_finding("some_value")
    OfflineHeuristicTriager().triage([finding])
    assert finding.confidence == "medium"


def test_get_triager_without_llm_flag_returns_offline():
    assert isinstance(get_triager(use_llm=False), OfflineHeuristicTriager)


def test_get_triager_without_api_key_falls_back_to_offline(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    triager = get_triager(use_llm=True)
    assert isinstance(triager, OfflineHeuristicTriager)
    assert "ANTHROPIC_API_KEY is not set" in capsys.readouterr().err


def test_get_triager_without_anthropic_package_falls_back_to_offline(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    monkeypatch.setitem(sys.modules, "anthropic", None)  # simulate package not installed
    triager = get_triager(use_llm=True)
    assert isinstance(triager, OfflineHeuristicTriager)
    assert "not installed" in capsys.readouterr().err


def test_anthropic_triager_only_sends_redacted_values(monkeypatch):
    """The prompt payload must never contain the raw secret -- only the
    redacted preview, variable name, and file path."""
    captured = {}

    class FakeMessages:
        def create(self, **kwargs):
            captured["kwargs"] = kwargs
            verdicts = [{"verdict": "FALSE_POSITIVE", "reason": "looks like a UUID"}]
            block = types.SimpleNamespace(type="text", text=json.dumps(verdicts))
            return types.SimpleNamespace(content=[block])

    class FakeAnthropic:
        def __init__(self, api_key=None):
            self.messages = FakeMessages()

    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)

    real_secret = "zQ9kLp2XwR8vT4mN6bY1cF7hJ3sD5aE0"
    finding = _generic_finding("correlation_hash")
    finding.redacted = "zQ9k...5aE0"
    assert real_secret not in finding.redacted

    triager = AnthropicTriager(api_key="sk-fake")
    triager.triage([finding])

    sent_payload = captured["kwargs"]["messages"][0]["content"]
    assert real_secret not in sent_payload
    assert finding.redacted in sent_payload
    assert finding.confidence == "low"
    assert finding.triage_reason == "looks like a UUID"


def test_anthropic_triager_falls_back_gracefully_on_api_error(monkeypatch):
    class FakeMessages:
        def create(self, **kwargs):
            raise RuntimeError("network down")

    class FakeAnthropic:
        def __init__(self, api_key=None):
            self.messages = FakeMessages()

    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)

    finding = _generic_finding("correlation_hash")
    triager = AnthropicTriager(api_key="sk-fake")
    result = triager.triage([finding])

    assert result[0].confidence == "high"  # untouched dataclass default, no crash
