"""Load and apply the detection rule pack (`data/rules.json`)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "rules.json"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    weight: float
    pattern: re.Pattern
    owasp: str
    atlas: str
    description: str
    indirect_boost: bool = False

    @classmethod
    def from_dict(cls, raw: dict) -> "Rule":
        flags = 0 if raw.get("case_sensitive") else re.IGNORECASE
        if raw.get("multiline"):
            flags |= re.MULTILINE
        weight = float(raw["weight"])
        if not 0.0 < weight < 1.0:
            raise ValueError(f"rule {raw['id']}: weight must be in (0, 1), got {weight}")
        return cls(
            id=raw["id"],
            name=raw["name"],
            category=raw["category"],
            weight=weight,
            pattern=re.compile(raw["pattern"], flags),
            owasp=raw.get("owasp", ""),
            atlas=raw.get("atlas", ""),
            description=raw.get("description", ""),
            indirect_boost=bool(raw.get("indirect_boost", False)),
        )


def load_rules(path: str | Path = DEFAULT_RULES_PATH) -> list[Rule]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = [Rule.from_dict(r) for r in data["rules"]]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids in rule pack")
    return rules
