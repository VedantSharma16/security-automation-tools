from llm_guardrail.llm_judge import LLMJudge, parse_judge_response


def test_parse_valid_and_clamped():
    r = parse_judge_response('Sure: {"injection": true, "confidence": 1.7, "reason": "x"}')
    assert r.is_injection is True and r.confidence == 1.0


def test_parse_rejects_malformed():
    assert parse_judge_response("no json") is None
    assert parse_judge_response('{"injection": "yes", "confidence": 0.9}') is None
    assert parse_judge_response('{"injection": true, "confidence": "high"}') is None


def test_judge_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    judge = LLMJudge()
    assert not judge.available and judge.classify("x", "input") is None
