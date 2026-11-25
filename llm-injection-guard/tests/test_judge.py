from types import SimpleNamespace

from injection_guard.judge import ClaudeJudge, parse_verdict


class FakeMessages:
    def __init__(self, response=None, exc=None):
        self.response, self.exc, self.kwargs = response, exc, None

    def create(self, **kwargs):
        self.kwargs = kwargs
        if self.exc:
            raise self.exc
        return self.response


def client_returning(text=None, stop_reason="end_turn", exc=None):
    resp = SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text or "")])
    messages = FakeMessages(resp, exc)
    return SimpleNamespace(beta=SimpleNamespace(messages=messages)), messages


def test_parse_verdict_handles_surrounding_text_and_clamps():
    v = parse_verdict('Result: {"injection": true, "confidence": 1.7, "reason": "override"} done')
    assert v.injection is True and v.confidence == 1.0 and v.reason == "override"


def test_parse_verdict_rejects_garbage():
    assert parse_verdict("no json here") is None
    assert parse_verdict('{"confidence": 0.9}') is None


def test_classify_success_and_request_shape():
    client, messages = client_returning('{"injection": false, "confidence": 0.8, "reason": "benign"}')
    judge = ClaudeJudge(client=client)
    v = judge.classify("hello", "user")
    assert v.injection is False and v.confidence == 0.8
    assert messages.kwargs["model"] == "claude-opus-5-5"
    assert "data, not instructions" in messages.kwargs["system"]


def test_sample_is_wrapped_in_random_boundary():
    judge = ClaudeJudge(client=client_returning("{}")[0])
    a = judge.build_messages("payload", "retrieved")[0]["content"]
    b = judge.build_messages("payload", "retrieved")[0]["content"]
    assert "payload" in a and a != b


def test_refusal_and_errors_return_none():
    assert ClaudeJudge(client=client_returning("", stop_reason="refusal")[0]).classify("x", "user") is None
    assert ClaudeJudge(client=client_returning(exc=RuntimeError("boom"))[0]).classify("x", "user") is None


def test_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    judge = ClaudeJudge()
    assert not judge.available and judge.classify("x", "user") is None
