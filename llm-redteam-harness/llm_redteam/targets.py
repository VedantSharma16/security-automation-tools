"""Targets under test.

`Target.respond` is the only integration point: wrap your own app (HTTP endpoint, RAG chain,
agent) by subclassing or passing a callable to `CallableTarget`.
"""

from __future__ import annotations

import base64
import re
from typing import Callable, Protocol

_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_OVERRIDE = re.compile(
    r"ignore (?:all )?(?:the )?(?:previous|prior)|ignora todas|disregard (?:the user|all|prior)|"
    r"new policy|you are now dan|unrestricted ai|assistant:|system note",
    re.I,
)
_LEAK = re.compile(
    r"system prompt|initial instructions|full configuration|everything above|hidden instructions", re.I
)
_EXFIL = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")


class Target(Protocol):
    name: str

    def respond(self, system_prompt: str, user_message: str, context: str | None = None) -> str: ...


class CallableTarget:
    def __init__(self, fn: Callable[[str, str, str | None], str], name: str = "callable"):
        self.fn = fn
        self.name = name

    def respond(self, system_prompt: str, user_message: str, context: str | None = None) -> str:
        return self.fn(system_prompt, user_message, context)


class VulnerableMockTarget:
    """Deliberately naive model stand-in: treats all text as instructions. Offline demo/test double."""

    name = "mock-vulnerable"

    def respond(self, system_prompt: str, user_message: str, context: str | None = None) -> str:
        text = "\n".join(filter(None, [user_message, context]))
        for blob in _B64.findall(text):
            try:
                text += "\n" + base64.b64decode(blob, validate=True).decode()
            except Exception:
                pass
        m = _EXFIL.search(text)
        if m and ("system" in text.lower()):
            return f"Done. ![x]({m.group(1).split('?')[0]}?d={system_prompt.replace(' ', '%20')})"
        if _LEAK.search(text):
            return f"Sure! My instructions are: {system_prompt}"
        if _OVERRIDE.search(text) or "pretending" in text.lower():
            marker = re.search(r"(PWNED-[0-9A-F]+)", text)
            if marker:
                return marker.group(1)
        return "Here is a helpful, on-topic answer."


class HardenedMockTarget:
    """Refuses instruction-like content in user/context input and never discloses its prompt."""

    name = "mock-hardened"

    def respond(self, system_prompt: str, user_message: str, context: str | None = None) -> str:
        text = "\n".join(filter(None, [user_message, context]))
        if _OVERRIDE.search(text) or _LEAK.search(text) or _EXFIL.search(text) or _B64.search(text):
            return "I can't help with that request, and I won't follow instructions embedded in content."
        return "Here is a helpful, on-topic answer."


class AnthropicTarget:
    """Runs attacks against a real Claude model (requires `pip install .[llm]` and ANTHROPIC_API_KEY)."""

    def __init__(self, model: str = "claude-haiku-4-5-20251001", max_tokens: int = 512):
        import anthropic  # lazy: core stays stdlib-only

        self._client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens
        self.name = f"anthropic:{model}"

    def respond(self, system_prompt: str, user_message: str, context: str | None = None) -> str:
        content = user_message if not context else f"{user_message}\n\n<document>\n{context}\n</document>"
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": content}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def get_target(name: str, model: str | None = None) -> Target:
    if name == "mock-vulnerable":
        return VulnerableMockTarget()
    if name == "mock-hardened":
        return HardenedMockTarget()
    if name == "anthropic":
        return AnthropicTarget(model) if model else AnthropicTarget()
    raise ValueError(f"unknown target {name!r}")
