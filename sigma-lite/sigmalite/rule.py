"""Sigma rule model and loading/validation."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import yamlmini

LEVELS = ("informational", "low", "medium", "high", "critical")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    title: str
    detection: dict[str, Any]
    condition: str
    id: str = ""
    level: str = "medium"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, Any] = field(default_factory=dict)
    path: str = ""

    @property
    def attack_techniques(self) -> list[str]:
        return [t[7:].upper() for t in self.tags if t.lower().startswith("attack.t")]

    @property
    def attack_tactics(self) -> list[str]:
        return [
            t[7:] for t in self.tags
            if t.lower().startswith("attack.") and not t.lower().startswith("attack.t1")
            and not t.lower().startswith("attack.s") and not t.lower().startswith("attack.g")
        ]


def from_dict(doc: Any, path: str = "") -> Rule:
    if not isinstance(doc, dict):
        raise RuleError(f"{path}: rule must be a mapping")
    title = doc.get("title")
    if not title or not isinstance(title, str):
        raise RuleError(f"{path}: missing 'title'")
    det = doc.get("detection")
    if not isinstance(det, dict):
        raise RuleError(f"{title}: missing 'detection' mapping")
    det = dict(det)
    cond = det.pop("condition", None)
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    if not isinstance(cond, str) or not cond.strip():
        raise RuleError(f"{title}: detection needs a 'condition'")
    if not det:
        raise RuleError(f"{title}: detection has no selections")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{title}: invalid level {level!r}")
    tags = doc.get("tags") or []
    if not isinstance(tags, list):
        raise RuleError(f"{title}: 'tags' must be a list")
    return Rule(
        title=title, detection=det, condition=cond.strip(), id=str(doc.get("id") or ""),
        level=level, description=str(doc.get("description") or ""),
        tags=[str(t) for t in tags], logsource=doc.get("logsource") or {}, path=path,
    )


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    try:
        return from_dict(yamlmini.loads(path.read_text(encoding="utf-8")), str(path))
    except yamlmini.YamlError as exc:
        raise RuleError(f"{path}: {exc}") from exc


def load_rules(location: str | Path) -> list[Rule]:
    location = Path(location)
    if not location.exists():
        raise RuleError(f"{location}: no such file or directory")
    files = [location] if location.is_file() else sorted(
        list(location.rglob("*.yml")) + list(location.rglob("*.yaml")))
    if not files:
        raise RuleError(f"{location}: no .yml/.yaml rules found")
    return [load_rule(f) for f in files]
