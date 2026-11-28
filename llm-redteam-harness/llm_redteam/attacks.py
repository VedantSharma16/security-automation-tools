"""Attack corpus loading and per-run rendering."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from llm_redteam.textutils import apply_transform

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_ATTACKS = DATA_DIR / "attacks.json"
DEFAULT_BENIGN = DATA_DIR / "benign.json"

VALID_GOALS = {"marker", "canary", "system_prompt", "exfil"}
VALID_DELIVERY = {"user", "document"}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM07": "System Prompt Leakage",
}

DEFAULT_QUESTION = "Can you help me with my order?"


@dataclass(frozen=True)
class Attack:
    id: str
    name: str
    category: str
    owasp: str
    severity: str
    delivery: str
    goal: str
    payload: str
    question: str = DEFAULT_QUESTION
    transform: str | None = None
    wrapper: str | None = None

    def __post_init__(self) -> None:
        if self.goal not in VALID_GOALS:
            raise ValueError(f"{self.id}: invalid goal {self.goal!r}")
        if self.delivery not in VALID_DELIVERY:
            raise ValueError(f"{self.id}: invalid delivery {self.delivery!r}")
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"{self.id}: invalid severity {self.severity!r}")
        if self.goal == "marker" and "{marker}" not in self.payload:
            raise ValueError(f"{self.id}: marker-goal attack must contain {{marker}}")

    def render(self, marker: str) -> "RenderedAttack":
        text = self.payload.replace("{marker}", marker)
        text = apply_transform(self.transform, text)
        if self.wrapper:
            text = self.wrapper.replace("{encoded}", text)
        if self.delivery == "document":
            return RenderedAttack(self, marker, user_message=self.question, documents=[text])
        return RenderedAttack(self, marker, user_message=text, documents=[])


@dataclass
class RenderedAttack:
    attack: Attack
    marker: str
    user_message: str
    documents: list[str] = field(default_factory=list)

    @property
    def injected_text(self) -> str:
        """The attacker-controlled text, wherever it was delivered."""
        return self.documents[0] if self.documents else self.user_message


def new_marker() -> str:
    return "PWN-" + secrets.token_hex(4).upper()


def load_attacks(path: str | Path = DEFAULT_ATTACKS, categories: list[str] | None = None) -> list[Attack]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    attacks = [Attack(**entry) for entry in raw["attacks"]]
    ids = [a.id for a in attacks]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate attack ids in corpus")
    if categories:
        wanted = set(categories)
        attacks = [a for a in attacks if a.category in wanted]
    return attacks


def load_benign(path: str | Path = DEFAULT_BENIGN) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return list(json.load(fh)["prompts"])
