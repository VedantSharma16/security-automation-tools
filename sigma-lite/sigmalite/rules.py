"""Rule loading, validation (linting) and evaluation."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from .condition import ConditionError, evaluate, parse_condition, referenced_names
from .matcher import MatchError, match_selection, split_key

LEVELS = ("informational", "low", "medium", "high", "critical")
_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z_]+)$")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    detection: dict
    condition: object  # parsed AST
    tags: list[str] = field(default_factory=list)
    description: str = ""
    source: str = ""

    @property
    def techniques(self) -> list[str]:
        return sorted(t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d{4}", t))

    @property
    def tactics(self) -> list[str]:
        return sorted(
            t.split(".", 1)[1] for t in self.tags
            if _ATTACK_TAG.match(t) and not re.match(r"attack\.t\d{4}", t)
        )

    def matches(self, event: dict) -> bool:
        results = {
            name: match_selection(event, sel)
            for name, sel in self.detection.items()
            if name != "condition"
        }
        return evaluate(self.condition, results)


def build_rule(data: dict, source: str = "") -> Rule:
    """Validate a rule mapping and return a Rule. Raises RuleError."""
    problems = lint_rule(data)
    if problems:
        raise RuleError(f"{source or data.get('id', '?')}: " + "; ".join(problems))
    return Rule(
        id=data["id"], title=data["title"], level=data.get("level", "medium"),
        detection=data["detection"], condition=parse_condition(data["detection"]["condition"]),
        tags=data.get("tags", []), description=data.get("description", ""), source=source,
    )


def lint_rule(data: dict) -> list[str]:
    """Return a list of human-readable problems (empty == clean)."""
    problems: list[str] = []
    for req in ("id", "title", "detection"):
        if req not in data:
            problems.append(f"missing required field '{req}'")
    if problems:
        return problems
    if data.get("level", "medium") not in LEVELS:
        problems.append(f"level must be one of {', '.join(LEVELS)}")
    for tag in data.get("tags", []):
        if tag.startswith("attack.") and not _ATTACK_TAG.match(tag):
            problems.append(f"malformed ATT&CK tag {tag!r}")
    det = data["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        return problems + ["detection needs a 'condition'"]
    selections = {k: v for k, v in det.items() if k != "condition"}
    if not selections:
        return problems + ["detection defines no selections"]
    for name, sel in selections.items():
        for item in sel if isinstance(sel, list) else [sel]:
            if not isinstance(item, dict) or not item:
                problems.append(f"selection '{name}' must be a non-empty mapping")
                continue
            for key in item:
                try:
                    split_key(key)
                except MatchError as exc:
                    problems.append(str(exc))
    try:
        ast = parse_condition(det["condition"])
    except ConditionError as exc:
        return problems + [f"bad condition: {exc}"]
    used = set()
    for ref in referenced_names(ast):
        hits = [n for n in selections if fnmatchcase(n, ref)]
        if not hits:
            problems.append(f"condition references undefined selection '{ref}'")
        used.update(hits)
    if "them" not in det["condition"]:
        for name in selections:
            if name not in used:
                problems.append(f"selection '{name}' is never used by the condition")
    return problems


def _read(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yml", ".yaml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise RuleError(f"{path}: install pyyaml to load YAML rules") from exc
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuleError(f"{path}: invalid JSON ({exc})") from exc


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.json|yml|yaml`` under a directory."""
    p = Path(path)
    files = sorted(f for f in p.rglob("*") if f.suffix in (".json", ".yml", ".yaml")) if p.is_dir() else [p]
    rules = [build_rule(_read(f), source=str(f)) for f in files]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule ids: {', '.join(sorted(dupes))}")
    return rules
