"""Sigma rule loading, compilation and linting."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .condition import ConditionError, Node, parse_condition
from .matcher import MatcherError, Predicate, compile_detection_item

__all__ = [
    "Rule", "RuleError", "LintIssue", "load_rule", "load_rules", "lint_rule", "lint_rules",
    "LEVELS",
]

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
_TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
_TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
}


class RuleError(ValueError):
    """Raised when a rule cannot be loaded or compiled."""


@dataclass
class Rule:
    """A compiled, ready-to-evaluate Sigma rule."""

    id: str
    title: str
    level: str
    detection: dict[str, Any]
    condition: Node
    predicates: dict[str, Predicate]
    status: str = "experimental"
    description: str = ""
    author: str = ""
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str = ""

    # ---------------------------------------------------------------- ATT&CK
    @property
    def techniques(self) -> list[str]:
        return sorted(t.split(".", 1)[1].upper() for t in self.tags if _TECHNIQUE_RE.match(t))

    @property
    def tactics(self) -> list[str]:
        return sorted(
            t.split(".", 1)[1].lower()
            for t in self.tags
            if t.lower().startswith("attack.") and t.split(".", 1)[1].lower() in _TACTICS
        )

    def tactic_technique_pairs(self) -> list[tuple[str, str]]:
        """Pair each technique with the tactic tag(s) that precede it.

        Sigma rules conventionally list a tactic followed by the techniques
        that serve it (``attack.execution, attack.t1059.001, attack.defense_evasion,
        attack.t1027``). Consecutive tactic tags form a group that shares the
        techniques after it (``attack.persistence, attack.execution,
        attack.t1053.005``). Techniques before any tactic are ``unmapped``.
        """
        pairs: list[tuple[str, str]] = []
        group: list[str] = []
        last_was_tactic = False
        for tag in self.tags:
            low = tag.lower()
            if not low.startswith("attack."):
                continue
            rest = low.split(".", 1)[1]
            if rest in _TACTICS:
                group = group + [rest] if last_was_tactic else [rest]
                last_was_tactic = True
            elif _TECHNIQUE_RE.match(low):
                pairs.extend((tactic, rest.upper()) for tactic in (group or ["unmapped"]))
                last_was_tactic = False
        return pairs

    # ------------------------------------------------------------ evaluation
    def applies_to(self, event: Mapping[str, Any]) -> bool:
        """Check the rule's logsource against optional event metadata.

        Events may carry a ``logsource`` dict (``product``/``category``/
        ``service``). Keys missing on either side are treated as wildcards so
        unlabelled events are evaluated by every rule.
        """
        meta = event.get("logsource")
        if not isinstance(meta, Mapping):
            return True
        for key in ("product", "category", "service"):
            want, have = self.logsource.get(key), meta.get(key)
            if want and have and str(want).lower() != str(have).lower():
                return False
        return True

    def evaluate(self, event: Mapping[str, Any]) -> tuple[bool, list[str]]:
        """Return ``(matched, identifiers_that_matched)`` for one event."""
        cache: dict[str, bool] = {}

        def resolve(name: str) -> bool:
            if name not in cache:
                cache[name] = self.predicates[name](event)
            return cache[name]

        matched = self.condition.evaluate(resolve)
        if not matched:
            return False, []
        # Explainability: report every identifier that fired, not just the
        # ones short-circuit evaluation happened to touch.
        hits = sorted(n for n in self.condition.identifiers() if resolve(n))
        return True, hits

    def matches(self, event: Mapping[str, Any]) -> bool:
        return self.applies_to(event) and self.evaluate(event)[0]


# ---------------------------------------------------------------------- loading


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def compile_rule(doc: Mapping[str, Any], source: str = "<memory>") -> Rule:
    """Compile a parsed Sigma YAML document into a :class:`Rule`."""
    if not isinstance(doc, Mapping):
        raise RuleError(f"{source}: rule must be a YAML mapping")
    for key in ("title", "detection"):
        if key not in doc:
            raise RuleError(f"{source}: missing required key {key!r}")
    detection = doc["detection"]
    if not isinstance(detection, Mapping) or "condition" not in detection:
        raise RuleError(f"{source}: detection must be a mapping with a 'condition'")

    identifiers = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
    if not identifiers:
        raise RuleError(f"{source}: detection defines no search identifiers")

    predicates: dict[str, Predicate] = {}
    for name, item in identifiers.items():
        try:
            predicates[name] = compile_detection_item(item)
        except MatcherError as exc:
            raise RuleError(f"{source}: detection '{name}': {exc}") from None
    try:
        condition = parse_condition(detection["condition"], identifiers.keys())
    except ConditionError as exc:
        raise RuleError(f"{source}: condition: {exc}") from None

    logsource = doc.get("logsource") or {}
    return Rule(
        id=str(doc.get("id", "")),
        title=str(doc["title"]),
        level=str(doc.get("level", "medium")).lower(),
        status=str(doc.get("status", "experimental")).lower(),
        description=str(doc.get("description", "")).strip(),
        author=str(doc.get("author", "")),
        detection=dict(detection),
        condition=condition,
        predicates=predicates,
        tags=_as_list(doc.get("tags")),
        logsource={str(k): str(v) for k, v in logsource.items()} if isinstance(logsource, Mapping) else {},
        falsepositives=_as_list(doc.get("falsepositives")),
        references=_as_list(doc.get("references")),
        source=source,
    )


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from None
    return compile_rule(doc, source=str(path))


def _rule_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(x for x in p.rglob("*") if x.suffix in (".yml", ".yaml")))
        elif p.exists():
            files.append(p)
        else:
            raise RuleError(f"{p}: no such file or directory")
    return files


def load_rules(paths: Iterable[str | Path]) -> list[Rule]:
    """Load every ``.yml``/``.yaml`` rule from the given files/directories."""
    return [load_rule(f) for f in _rule_files(paths)]


# ---------------------------------------------------------------------- linting


@dataclass(frozen=True)
class LintIssue:
    source: str
    severity: str  # "error" | "warning"
    message: str

    def __str__(self) -> str:
        return f"{self.severity.upper():7} {self.source}: {self.message}"


def lint_rule(path: str | Path) -> list[LintIssue]:
    """Validate a single rule file against style and correctness checks."""
    path = Path(path)
    src = str(path)
    issues: list[LintIssue] = []

    def err(msg: str) -> None:
        issues.append(LintIssue(src, "error", msg))

    def warn(msg: str) -> None:
        issues.append(LintIssue(src, "warning", msg))

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        err(f"invalid YAML: {exc}")
        return issues

    try:
        rule = compile_rule(doc, source=src)
    except RuleError as exc:
        err(str(exc).removeprefix(f"{src}: "))
        return issues

    if not rule.id:
        err("missing 'id'")
    else:
        try:
            uuid.UUID(rule.id)
        except ValueError:
            err(f"id {rule.id!r} is not a valid UUID")
    if rule.level not in LEVELS:
        err(f"level {rule.level!r} not in {LEVELS}")
    if "status" in doc and rule.status not in STATUSES:
        err(f"status {rule.status!r} not in {STATUSES}")
    if not rule.logsource:
        err("missing 'logsource'")
    if not rule.description:
        warn("missing 'description'")
    if not rule.falsepositives:
        warn("missing 'falsepositives' (document expected benign triggers)")
    if len(rule.title) > 110:
        warn("title longer than 110 characters")

    for tag in rule.tags:
        low = tag.lower()
        if low.startswith("attack."):
            rest = low.split(".", 1)[1]
            if not (_TECHNIQUE_RE.match(low) or rest in _TACTICS or re.match(r"^[gs]\d{4}$", rest)):
                err(f"unknown ATT&CK tag {tag!r}")
        if tag != tag.lower():
            warn(f"tag {tag!r} should be lowercase")
    if rule.tags and not rule.techniques:
        warn("no ATT&CK technique tag (attack.tXXXX)")

    unused = set(rule.predicates) - rule.condition.identifiers()
    for name in sorted(unused):
        warn(f"detection identifier {name!r} is never used by the condition")
    return issues


def lint_rules(paths: Iterable[str | Path]) -> list[LintIssue]:
    """Lint all rule files, including cross-rule checks such as duplicate ids."""
    issues: list[LintIssue] = []
    seen: dict[str, str] = {}
    for f in _rule_files(paths):
        issues.extend(lint_rule(f))
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        rid = str(doc.get("id", "")) if isinstance(doc, Mapping) else ""
        if rid:
            if rid in seen:
                issues.append(LintIssue(str(f), "error", f"duplicate id {rid} (also in {seen[rid]})"))
            else:
                seen[rid] = str(f)
    return issues
