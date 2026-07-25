"""Minimal fakes standing in for the Anthropic SDK's response shape, so the
tool-calling loop in LLMAgent can be unit-tested without network access or
the ``anthropic`` package installed.
"""

from __future__ import annotations


class FakeTextBlock:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class FakeToolUseBlock:
    def __init__(self, name: str, input: dict, id: str = "tool_call_1"):
        self.type = "tool_use"
        self.name = name
        self.input = input
        self.id = id


class FakeResponse:
    def __init__(self, content: list):
        self.content = content


class FakeMessages:
    def __init__(self, responses: list[FakeResponse]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self._responses:
            raise AssertionError("FakeMessages.create called more times than scripted responses provided")
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses: list[FakeResponse]):
        self.messages = FakeMessages(responses)
