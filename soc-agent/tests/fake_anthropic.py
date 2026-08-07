"""A minimal fake of the ``anthropic`` SDK surface used by llm_client.py,
so the tool-calling loop's control flow can be unit tested deterministically
without a real API key or network access."""

from __future__ import annotations

import types


class FakeBlock:
    def __init__(self, type, text=None, name=None, input=None, id=None):
        self.type = type
        self.text = text
        self.name = name
        self.input = input
        self.id = id


class FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeMessages:
    def __init__(self, responses):
        self._responses = iter(responses)

    def create(self, **kwargs):
        return next(self._responses)


class _FakeAnthropicClient:
    def __init__(self, api_key=None, responses=None):
        self.messages = _FakeMessages(responses)


def make_fake_anthropic_module(responses):
    """Build a fake module object suitable for injecting into sys.modules
    under the name 'anthropic', pre-loaded with a scripted sequence of
    ``FakeResponse`` objects returned in order from ``messages.create``."""
    module = types.ModuleType("anthropic")
    module.Anthropic = lambda api_key=None: _FakeAnthropicClient(api_key=api_key, responses=responses)
    return module
