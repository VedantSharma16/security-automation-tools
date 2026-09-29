"""Attack corpus loading and per-run rendering."""

from __future__ import annotations

import base64
import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "data" / "attacks.json"
_B64_TOKEN = re.compile(r"<<b64:(.*?)>>", re.S)
SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 5}


@dataclass(frozen=True)
class Attack:
    id: str
    category: str
    owasp: str
    severity: str
    title: str
    prompt: str
    context: str | None = None


@dataclass(frozen=True)
class RenderedAttack:
    attack: Attack
    prompt: str
    context: str | None
    marker: str


def load_attacks(path: Path | str = DEFAULT_CORPUS, categories: set[str] | None = None) -> list[Attack]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    attacks = []
    for item in raw:
        if item.get("severity") not in SEVERITY_WEIGHT:
            raise ValueError(f"{item.get('id')}: invalid severity {item.get('severity')!r}")
        attacks.append(Attack(**{k: item.get(k) for k in Attack.__dataclass_fields__}))
    ids = [a.id for a in attacks]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate attack ids in corpus")
    if categories:
        attacks = [a for a in attacks if a.category in categories]
    return attacks


def new_marker() -> str:
    """Random per-run marker so a model cannot 'pass' by having memorized a fixed string."""
    return "PWNED-" + secrets.token_hex(4).upper()


def new_canary() -> str:
    """Random secret planted in the system prompt; its appearance in output proves leakage."""
    return "CANARY-" + secrets.token_hex(6)


def render(attack: Attack, marker: str) -> RenderedAttack:
    def sub(text: str | None) -> str | None:
        if text is None:
            return None
        text = text.replace("{MARKER}", marker)
        return _B64_TOKEN.sub(lambda m: base64.b64encode(m.group(1).encode()).decode(), text)

    return RenderedAttack(attack, sub(attack.prompt), sub(attack.context), marker)
