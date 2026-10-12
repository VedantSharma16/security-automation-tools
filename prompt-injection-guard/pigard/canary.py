"""Canary tokens: plant a secret marker in the system prompt, detect it in outputs."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field


@dataclass
class CanaryToken:
    value: str = field(default_factory=lambda: f"CNRY-{secrets.token_hex(6)}")

    def embed(self, system_prompt: str) -> str:
        """Append an instruction-proof marker; any output containing it is a leak."""
        return f"{system_prompt}\n[internal-id: {self.value}]"


def check_leak(output: str, token: CanaryToken, min_fragment: int = 8) -> bool:
    """True if the canary (or a long fragment, defeating trivial splitting) appears in ``output``."""
    squashed = re.sub(r"[\s\-_.​]+", "", output).lower()
    full = re.sub(r"[\s\-_.]+", "", token.value).lower()
    if full in squashed:
        return True
    return any(full[i:i + min_fragment] in squashed for i in range(len(full) - min_fragment + 1))
