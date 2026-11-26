import pytest

from detlab.author import (
    RuleAuthor,
    _best_common_substring,
    extract_yaml,
    synthesize_rule,
    validate_candidate,
)
from detlab.rules import compile_rule, yaml_load

POS = [
    {"Image": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil.exe cl Security", "ProcessId": 1, "Hostname": "A"},
    {"Image": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil cl System", "ProcessId": 2, "Hostname": "B"},
]
NEG = [
    {"Image": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil qe Security", "ProcessId": 3, "Hostname": "A"},
    {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c echo cl x", "ProcessId": 4, "Hostname": "A"},
]

GOOD_RULE = """```yaml
title: Event log cleared with wevtutil
id: 0b5a3c3e-1d2f-4b1a-9c55-0d7e2f7c9a10
status: experimental
description: wevtutil cl
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\wevtutil.exe'
    CommandLine|contains: ' cl '
  condition: selection
falsepositives: [Admins rotating logs]
level: high
tags: [attack.defense_evasion, attack.t1070.001]
```"""

# Syntactically valid but too broad: fires on the benign 'qe' query.
BROAD_RULE = GOOD_RULE.replace("    CommandLine|contains: ' cl '\n", "")


class FakeLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def complete(self, system, prompt):
        self.prompts.append(prompt)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def test_extract_yaml_from_fenced_and_bare():
    assert extract_yaml("Here you go:\n```yaml\na: 1\n```\nthanks").strip() == "a: 1"
    assert extract_yaml("a: 1").strip() == "a: 1"


def test_validate_candidate_catches_lint_and_sample_failures():
    assert validate_candidate(extract_yaml(GOOD_RULE), POS, NEG) == []
    errors = validate_candidate(extract_yaml(BROAD_RULE), POS, NEG)
    assert errors == ["incorrectly matched true_negatives[0]"]
    assert validate_candidate("key: [unclosed", POS, NEG)[0].startswith("YAML does not parse")
    assert validate_candidate("- a list", POS, NEG) == ["response is not a YAML mapping"]


def test_llm_loop_feeds_errors_back_until_rule_passes():
    llm = FakeLLM([BROAD_RULE, GOOD_RULE])
    result = RuleAuthor(client=llm, max_iterations=3).draft("clear logs", POS, NEG)
    assert result.passed and result.final_source == "llm"
    assert [a.passed for a in result.attempts] == [False, True]
    # the second prompt must contain the rejected draft and the concrete failure
    assert "incorrectly matched true_negatives[0]" in llm.prompts[1]
    assert "Image|endswith" in llm.prompts[1]


def test_llm_failures_fall_back_to_synthesizer():
    llm = FakeLLM([BROAD_RULE, BROAD_RULE])
    result = RuleAuthor(client=llm, max_iterations=2).draft("clear logs", POS, NEG)
    assert [a.source for a in result.attempts] == ["llm", "llm", "synthesizer"]
    assert result.passed and result.final_source == "synthesizer"


def test_llm_exception_stops_calling_and_falls_back():
    llm = FakeLLM([RuntimeError("rate limited")])
    result = RuleAuthor(client=llm, max_iterations=3).draft("clear logs", POS, NEG)
    assert "LLM call failed: rate limited" in result.attempts[0].errors[0]
    assert result.passed and len(llm.prompts) == 1


def test_offline_synthesizer_builds_discriminating_rule():
    result = RuleAuthor(client=None).draft("Event log clearing", POS, NEG, level="high", tags=["attack.t1070.001"])
    assert result.passed
    data = yaml_load(result.rule_yaml)
    selection = data["detection"]["selection"]
    assert selection == {"CommandLine|contains": " cl ", "Image|endswith": "\\wevtutil.exe"}
    assert data["level"] == "high" and data["tags"] == ["attack.t1070.001"]
    # volatile per-host fields must never become detection logic
    assert not any(k.split("|")[0] in {"ProcessId", "Hostname"} for k in selection)


def test_synthesizer_uses_exact_value_when_shared():
    pos = [{"ParentImage": "C:\\a\\WINWORD.EXE", "Image": "C:\\Windows\\cmd.exe"}] * 2
    neg = [{"ParentImage": "C:\\Windows\\explorer.exe", "Image": "C:\\Windows\\cmd.exe"}]
    rule = compile_rule(yaml_load(synthesize_rule(pos, neg, "office child")))
    assert rule.matches(pos[0]) and not rule.matches(neg[0])


def test_synthesizer_with_no_usable_fields_emits_placeholder():
    text = synthesize_rule([{"ProcessId": 1}], [], "nothing")
    assert "REVIEW_ME" in text


def test_best_common_substring_prefers_fewest_negative_hits():
    assert _best_common_substring(["wevtutil.exe cl a", "wevtutil cl b"], ["wevtutil qe"]) == " cl "
    assert _best_common_substring(["abc", "xyz"], []) is None


def test_draft_requires_positive_samples():
    with pytest.raises(ValueError):
        RuleAuthor().draft("x", [], NEG)
