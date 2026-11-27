from types import SimpleNamespace

from llm_guardrail.judge import LLMJudge, build_prompt, parse_judgement


def test_parse_valid_json_with_surrounding_text():
    out = parse_judgement('Result: {"label": "injection", "confidence": 0.9, "reason": "override"}')
    assert out == {"label": "injection", "confidence": 0.9, "reason": "override"}


def test_parse_rejects_bad_output():
    assert parse_judgement("no json here") is None
    assert parse_judgement('{"label": "maybe", "confidence": 0.9}') is None
    assert parse_judgement('{"label": "benign", "confidence": 7}') is None
    assert parse_judgement('{"label": "benign", "confidence": "high"}') is None


def test_prompt_wraps_sample_in_random_delimiters():
    p1, p2 = build_prompt("x", "user", ["PI-001"]), build_prompt("x", "user", ["PI-001"])
    assert p1 != p2 and "<sample-" in p1 and "PI-001" in p1


class FakeClient:
    def __init__(self, text=None, exc=None, stop_reason="end_turn"):
        self.text, self.exc, self.stop_reason, self.kwargs = text, exc, stop_reason, None
        self.messages = self

    def create(self, **kwargs):
        self.kwargs = kwargs
        if self.exc:
            raise self.exc
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type="text", text=self.text)])


def test_live_judge_with_fake_client():
    client = FakeClient('{"label": "benign", "confidence": 0.85, "reason": "discussion"}')
    judge = LLMJudge(client=client)
    assert judge.is_live
    assert judge.classify("text", "retrieved", [])["label"] == "benign"
    assert client.kwargs["model"] == "claude-opus-5-5"


def test_judge_fails_closed_to_rule_verdict():
    assert LLMJudge(client=FakeClient(exc=RuntimeError("boom"))).classify("t", "user", []) is None
    assert LLMJudge(client=FakeClient("{}", stop_reason="refusal")).classify("t", "user", []) is None


def test_offline_judge_returns_none(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    judge = LLMJudge()
    assert not judge.is_live
    assert judge.classify("t", "user", []) is None
