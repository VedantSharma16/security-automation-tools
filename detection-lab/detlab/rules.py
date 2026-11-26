"""Loading, compiling and linting Sigma-format detection rules."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .condition import Node, evaluate, parse_condition, referenced
from .matcher import RuleSyntaxError, Selection

LEVELS = ["informational", "low", "medium", "high", "critical"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
_TACTIC_TAGS = {
    "attack.reconnaissance", "attack.resource_development", "attack.initial_access",
    "attack.execution", "attack.persistence", "attack.privilege_escalation",
    "attack.defense_evasion", "attack.credential_access", "attack.discovery",
    "attack.lateral_movement", "attack.collection", "attack.command_and_control",
    "attack.exfiltration", "attack.impact",
}
_GROUP_OR_SOFTWARE_TAG = re.compile(r"^attack\.[gs]\d{4}$")


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys.

    Plain PyYAML silently keeps the *last* duplicate, so a rule with two
    ``CommandLine|contains`` entries in one selection would quietly lose half
    its logic. That is a classic detection-engineering bug; fail loudly.
    """


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r} (later value would silently override the earlier one)",
                key_node.start_mark,
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def yaml_load(text: str) -> Any:
    return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass


def yaml_load_all(text: str) -> list[Any]:
    return [d for d in yaml.load_all(text, Loader=_StrictLoader) if d is not None]  # noqa: S506


@dataclass
class LintIssue:
    severity: str  # "error" | "warning"
    message: str

    def __str__(self) -> str:
        return f"{self.severity.upper()}: {self.message}"


@dataclass
class Rule:
    """A compiled detection rule, ready to evaluate against events."""

    id: str
    title: str
    level: str
    status: str
    description: str
    tags: list[str]
    logsource: dict[str, Any]
    falsepositives: list[str]
    selections: dict[str, Selection]
    conditions: list[Node]
    raw: dict[str, Any] = field(repr=False)
    source: str = ""

    def matches(self, event: dict[str, Any]) -> bool:
        cache: dict[str, bool] = {}

        def resolve(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].matches(event)
            return cache[name]

        return any(evaluate(cond, resolve) for cond in self.conditions)

    def matched_selections(self, event: dict[str, Any]) -> list[str]:
        return [name for name, sel in self.selections.items() if sel.matches(event)]

    @property
    def techniques(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if _TECHNIQUE_TAG.match(t)})

    @property
    def tactics(self) -> list[str]:
        return sorted({t.split(".", 1)[1] for t in self.tags if t in _TACTIC_TAGS})

    @property
    def level_rank(self) -> int:
        return LEVELS.index(self.level) if self.level in LEVELS else 0


def compile_rule(data: dict[str, Any], source: str = "<memory>") -> Rule:
    """Compile a parsed YAML mapping into a :class:`Rule` (raises on hard errors)."""
    if not isinstance(data, dict):
        raise RuleSyntaxError("rule document is not a mapping")
    detection = data.get("detection")
    if not isinstance(detection, dict):
        raise RuleSyntaxError("rule is missing a 'detection' mapping")
    if "condition" not in detection:
        raise RuleSyntaxError("detection block is missing 'condition'")
    if "timeframe" in detection:
        raise RuleSyntaxError("'timeframe' (aggregation) is not supported")

    selections = {
        str(name): Selection.parse(str(name), body)
        for name, body in detection.items()
        if name != "condition"
    }
    if not selections:
        raise RuleSyntaxError("detection block defines no selections")
    raw_conditions = detection["condition"]
    cond_list = raw_conditions if isinstance(raw_conditions, list) else [raw_conditions]
    conditions = [parse_condition(str(c), list(selections)) for c in cond_list]

    tags = [str(t).lower() for t in data.get("tags") or []]
    return Rule(
        id=str(data.get("id") or ""),
        title=str(data.get("title") or ""),
        level=str(data.get("level") or "medium").lower(),
        status=str(data.get("status") or "experimental").lower(),
        description=str(data.get("description") or ""),
        tags=tags,
        logsource=dict(data.get("logsource") or {}),
        falsepositives=[str(f) for f in data.get("falsepositives") or []],
        selections=selections,
        conditions=conditions,
        raw=data,
        source=source,
    )


def parse_rule_text(text: str, source: str = "<memory>") -> Rule:
    try:
        data = yaml_load(text)
    except yaml.YAMLError as exc:
        raise RuleSyntaxError(f"invalid YAML: {exc}") from exc
    return compile_rule(data, source)


def lint_rule_data(data: Any) -> list[LintIssue]:
    """Return every problem with a rule: compile errors plus metadata hygiene."""
    issues: list[LintIssue] = []
    try:
        rule = compile_rule(data)
    except RuleSyntaxError as exc:
        return [LintIssue("error", str(exc))]

    for required in ("title", "id", "logsource", "level"):
        if not data.get(required):
            issues.append(LintIssue("error", f"missing required field '{required}'"))
    if rule.id:
        try:
            uuid.UUID(rule.id)
        except ValueError:
            issues.append(LintIssue("error", f"id {rule.id!r} is not a UUID"))
    if data.get("level") and rule.level not in LEVELS:
        issues.append(LintIssue("error", f"level {rule.level!r} must be one of {LEVELS}"))
    if rule.status not in STATUSES:
        issues.append(LintIssue("warning", f"status {rule.status!r} is not a standard Sigma status"))
    if not rule.description:
        issues.append(LintIssue("warning", "missing 'description'"))
    if len(rule.title) > 110:
        issues.append(LintIssue("warning", "title is longer than 110 characters"))
    if not any(k in rule.logsource for k in ("product", "category", "service")):
        issues.append(LintIssue("warning", "logsource should name a product, category or service"))
    if not rule.falsepositives:
        issues.append(LintIssue("warning", "no 'falsepositives' documented"))

    for tag in rule.tags:
        if tag.startswith("attack.") and not (
            _TECHNIQUE_TAG.match(tag) or tag in _TACTIC_TAGS or _GROUP_OR_SOFTWARE_TAG.match(tag)
        ):
            issues.append(LintIssue("error", f"malformed ATT&CK tag '{tag}'"))
    if not rule.techniques:
        issues.append(LintIssue("warning", "no ATT&CK technique tag (attack.tNNNN)"))
    if rule.techniques and not rule.tactics:
        issues.append(LintIssue("warning", "technique tagged but no ATT&CK tactic tag"))

    used = set().union(*(referenced(c) for c in rule.conditions))
    for name in rule.selections:
        if name not in used:
            issues.append(LintIssue("warning", f"selection '{name}' is never used by the condition"))
    return issues


@dataclass
class RuleLoadResult:
    rules: list[Rule]
    errors: dict[str, str]  # source path -> error message


def load_rules(paths: list[Path | str]) -> RuleLoadResult:
    """Load every ``*.yml``/``*.yaml`` rule under the given files/directories.

    Multi-document YAML files are supported. A broken rule is reported in
    ``errors`` instead of aborting the whole load.
    """
    rules: list[Rule] = []
    errors: dict[str, str] = {}
    for file in _iter_rule_files(paths):
        try:
            docs = yaml_load_all(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors[str(file)] = f"invalid YAML: {exc}"
            continue
        for idx, doc in enumerate(docs):
            label = str(file) if len(docs) == 1 else f"{file}#{idx}"
            try:
                rules.append(compile_rule(doc, source=label))
            except RuleSyntaxError as exc:
                errors[label] = str(exc)
    return RuleLoadResult(rules=rules, errors=errors)


def iter_rule_documents(paths: list[Path | str]):
    """Yield ``(label, parsed_yaml_or_exception)`` for linting."""
    for file in _iter_rule_files(paths):
        try:
            docs = yaml_load_all(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            yield str(file), RuleSyntaxError(f"invalid YAML: {exc}")
            continue
        for idx, doc in enumerate(docs):
            yield (str(file) if len(docs) == 1 else f"{file}#{idx}"), doc


def _iter_rule_files(paths: list[Path | str]):
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix in {".yml", ".yaml"} and p.is_file())
        elif path.is_file():
            yield path
        else:
            raise FileNotFoundError(f"rule path not found: {path}")
