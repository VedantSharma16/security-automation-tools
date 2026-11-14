"""Taint-aware tool-call policy for agents.

The dangerous combination for an LLM agent is: (1) access to private data,
(2) exposure to untrusted content, and (3) a way to act or communicate
externally. Once untrusted content (a retrieved web page, an email, a tool
result) enters the context, the model's next tool call may be attacker-
steered. This module enforces that at the *tool boundary*, where it can be
done deterministically instead of hoping the model resisted the injection.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import SensitiveDataScanner, domain_allowed
from .findings import Action, Finding, strongest

_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_SHELL_META = re.compile(r"[;&|`<>]|\$\(|\$\{|\n")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    side_effects: bool = False  # writes, deletes, payments, messages, egress
    allowed_domains: tuple[str, ...] = ()  # for URLs / email recipients in args
    shell_args: tuple[str, ...] = ()  # args interpolated into a shell command

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "ToolSpec":
        return cls(
            name=name,
            side_effects=bool(data.get("side_effects", False)),
            allowed_domains=tuple(d.lower() for d in data.get("allowed_domains", ())),
            shell_args=tuple(data.get("shell_args", ())),
        )


@dataclass
class ToolPolicy:
    tools: dict[str, ToolSpec] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> "ToolPolicy":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls({name: ToolSpec.from_dict(name, spec) for name, spec in data.get("tools", {}).items()})

    def evaluate(self, name: str, args: dict, *, tainted: bool, injection_seen: bool) -> tuple[Action, list[Finding]]:
        spec = self.tools.get(name)
        if spec is None:
            return Action.BLOCK, [Finding("tool.not_allowlisted", "tool_policy", 0.9, "LLM06",
                                          f"Tool '{name}' is not in the allowlist")]

        findings: list[Finding] = []
        actions = [Action.ALLOW]
        strings = list(_iter_strings(args))

        for value in strings:
            for url in _URL.findall(value):
                if not domain_allowed(url, spec.allowed_domains):
                    findings.append(Finding("tool.url_not_allowlisted", "tool_policy", 0.85, "LLM06",
                                            f"'{name}' argument targets a non-allowlisted domain", evidence=url[:120]))
                    actions.append(Action.BLOCK)
            for match in _EMAIL.finditer(value):
                if spec.allowed_domains and not domain_allowed("x://" + match.group(1), spec.allowed_domains):
                    findings.append(Finding("tool.recipient_not_allowlisted", "tool_policy", 0.85, "LLM06",
                                            f"'{name}' recipient is outside allowlisted domains",
                                            evidence=match.group()))
                    actions.append(Action.BLOCK)

        for arg in spec.shell_args:
            value = args.get(arg)
            if isinstance(value, str) and _SHELL_META.search(value):
                findings.append(Finding("tool.shell_metacharacters", "tool_policy", 0.9, "LLM05",
                                        f"Shell metacharacters in '{arg}' (command injection)", evidence=value[:120]))
                actions.append(Action.BLOCK)

        dlp_findings, _ = SensitiveDataScanner(include_pii=False).scan("\n".join(strings))
        if dlp_findings:
            findings += [Finding("tool.secret_in_arguments", "tool_policy", 0.95, "LLM02",
                                 f"Secret passed to tool '{name}' ({f.rule_id})", evidence=f.evidence)
                         for f in dlp_findings]
            actions.append(Action.BLOCK)

        if spec.side_effects and injection_seen:
            findings.append(Finding("tool.side_effect_after_injection", "tool_policy", 0.9, "LLM06",
                                    f"Side-effecting tool '{name}' called after an injection was detected "
                                    "in this session"))
            actions.append(Action.BLOCK)
        elif spec.side_effects and tainted:
            findings.append(Finding("tool.side_effect_with_untrusted_context", "tool_policy", 0.5, "LLM06",
                                    f"Side-effecting tool '{name}' called while untrusted content is in "
                                    "context; human approval required"))
            actions.append(Action.REQUIRE_APPROVAL)

        return strongest(*actions), findings


def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)
