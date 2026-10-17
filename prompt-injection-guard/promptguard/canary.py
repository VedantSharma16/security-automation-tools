"""Canary tokens: plant a secret in the system prompt, detect it in model output."""

from __future__ import annotations

import secrets


class Canary:
    def __init__(self, token: str | None = None):
        self.token = token or f"CANARY-{secrets.token_hex(8)}"

    def instrument(self, system_prompt: str) -> str:
        """Append the canary so a prompt-extraction attack will echo it."""
        return f"{system_prompt}\n\n[internal marker, never output: {self.token}]"

    def leaked(self, model_output: str) -> bool:
        # Tolerate trivial obfuscation: case, whitespace and separators stripped.
        squash = lambda s: "".join(c for c in s.lower() if c.isalnum())
        return squash(self.token) in squash(model_output)
