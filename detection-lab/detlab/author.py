"""LLM-assisted detection authoring with a test-driven feedback loop.

Given an incident description plus labelled sample events (malicious
``positives`` and benign ``negatives``), the author agent iterates:

    draft rule ──▶ lint ──▶ run against samples ──▶ pass? ──▶ done
        ▲                                             │ no
        └──────── feed concrete errors back ◀─────────┘

The LLM never gets the last word: every draft is compiled by the same engine
that runs in production and must match every positive and no negative before
it is accepted. If no LLM is configured, or every LLM attempt fails, a
deterministic synthesizer derives a (deliberately conservative) rule
directly from the samples, so the command always produces something
reviewable and the whole loop is testable offline.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

import yaml

from .matcher import RuleSyntaxError
from .rules import compile_rule, lint_rule_data, yaml_load
from .testing import RuleTestCase, evaluate_case

DEFAULT_MODEL = "claude-sonnet-5-5"

SYSTEM_PROMPT = """You are a senior detection engineer writing Sigma rules.
Return exactly one Sigma rule as YAML inside a ```yaml fenced block and nothing else.
Requirements:
- Include title, id (a UUID), status: experimental, description, logsource, detection, falsepositives, level, tags.
- Tag with MITRE ATT&CK (attack.<tactic> and attack.tNNNN[.NNN]).
- Supported value modifiers: contains, startswith, endswith, re, all, cidr, windash, exists.
- No aggregation ('| count()') and no 'timeframe'.
- The rule MUST match every positive sample and MUST NOT match any negative sample.
- Prefer behavioural indicators (command-line flags, parent/child relationships) over
  brittle values (hostnames, usernames, PIDs, timestamps, hashes) so the rule generalises."""

# Fields that identify a specific host/run rather than a behaviour; never build detections on them.
VOLATILE_FIELDS = {
    "utctime", "timestamp", "@timestamp", "time", "eventtime", "processid", "parentprocessid",
    "processguid", "parentprocessguid", "hostname", "computer", "host", "logonid", "logonguid",
    "recordnumber", "eventrecordid", "hashes", "sha256", "md5", "sha1", "_logsource",
}
FIELD_PRIORITY = ["commandline", "image", "parentimage", "targetobject", "details", "targetfilename",
                  "originalfilename", "parentcommandline", "destinationport", "destinationhostname"]


class LLMClient(Protocol):
    def complete(self, system: str, prompt: str) -> str: ...


class AnthropicClient:
    """Thin wrapper over the Anthropic SDK (optional dependency)."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        import anthropic  # type: ignore  # imported lazily: optional dependency

        self.model = model
        self._client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def complete(self, system: str, prompt: str) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=1500,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in response.content if getattr(b, "type", "") == "text")


def default_client() -> LLMClient | None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        return AnthropicClient()
    except ImportError:
        return None


@dataclass
class Attempt:
    source: str  # "llm" | "synthesizer"
    rule_yaml: str
    errors: list[str]

    @property
    def passed(self) -> bool:
        return not self.errors


@dataclass
class AuthoringResult:
    rule_yaml: str | None
    passed: bool
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def final_source(self) -> str | None:
        return self.attempts[-1].source if self.attempts else None


def extract_yaml(text: str) -> str:
    """Pull the YAML body out of an LLM reply (fenced or bare)."""
    fenced = re.search(r"```(?:ya?ml)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    return (fenced.group(1) if fenced else text).strip() + "\n"


def validate_candidate(rule_yaml: str, positives: list[dict], negatives: list[dict]) -> list[str]:
    """Every reason a candidate rule is not acceptable (empty list = accept)."""
    try:
        data = yaml_load(rule_yaml)
    except yaml.YAMLError as exc:
        return [f"YAML does not parse: {exc}"]
    if not isinstance(data, dict):
        return ["response is not a YAML mapping"]
    errors = [str(i) for i in lint_rule_data(data) if i.severity == "error"]
    try:
        rule = compile_rule(data)
    except RuleSyntaxError as exc:
        return errors or [str(exc)]
    result = evaluate_case(rule, RuleTestCase(rule.id, positives, negatives))
    errors.extend(result.failure_messages())
    return errors


def _build_prompt(description: str, positives: list[dict], negatives: list[dict], history: list[Attempt]) -> str:
    parts = [
        f"Incident / behaviour to detect:\n{description.strip()}",
        "Positive samples (MUST match):\n" + json.dumps(positives, indent=2),
        "Negative samples (MUST NOT match):\n" + json.dumps(negatives, indent=2),
    ]
    if history:
        last = history[-1]
        parts.append(
            "Your previous draft was rejected by the validation harness:\n"
            f"```yaml\n{last.rule_yaml}```\nErrors:\n- " + "\n- ".join(last.errors)
            + "\nFix every error and return the corrected rule."
        )
    return "\n\n".join(parts)


class RuleAuthor:
    def __init__(self, client: LLMClient | None = None, max_iterations: int = 3):
        self.client = client
        self.max_iterations = max(1, max_iterations)

    def draft(
        self,
        description: str,
        positives: list[dict],
        negatives: list[dict],
        title: str | None = None,
        level: str = "medium",
        tags: list[str] | None = None,
        logsource: dict[str, str] | None = None,
    ) -> AuthoringResult:
        if not positives:
            raise ValueError("at least one positive sample is required")
        attempts: list[Attempt] = []

        if self.client is not None:
            for _ in range(self.max_iterations):
                try:
                    reply = self.client.complete(SYSTEM_PROMPT, _build_prompt(description, positives, negatives, attempts))
                except Exception as exc:  # network/SDK failure: stop calling the LLM, fall through
                    attempts.append(Attempt("llm", "", [f"LLM call failed: {exc}"]))
                    break
                candidate = extract_yaml(reply)
                attempt = Attempt("llm", candidate, validate_candidate(candidate, positives, negatives))
                attempts.append(attempt)
                if attempt.passed:
                    return AuthoringResult(candidate, True, attempts)

        synthesized = synthesize_rule(
            positives, negatives, description, title=title, level=level, tags=tags, logsource=logsource
        )
        attempt = Attempt("synthesizer", synthesized, validate_candidate(synthesized, positives, negatives))
        attempts.append(attempt)
        return AuthoringResult(synthesized, attempt.passed, attempts)


# --------------------------------------------------------------------------- #
# Deterministic synthesizer
# --------------------------------------------------------------------------- #

def _best_common_substring(values: list[str], negatives: list[str], min_len: int = 4) -> str | None:
    """Pick the substring shared by every value that best separates them from ``negatives``.

    Ranking: fewest negatives containing it, then aligned to token
    boundaries (``' cl '`` beats ``' cl s'``, which would only catch logs whose
    name starts with "s"), then longest. Leading/trailing spaces are kept on
    purpose: they act as word boundaries.
    """
    lowered = [v.lower() for v in values]
    neg = [n.lower() for n in negatives]
    shortest = min(lowered, key=len)[:300]
    best: tuple[int, int, int, str] | None = None
    seen: set[str] = set()
    for length in range(len(shortest), min_len - 1, -1):
        for start in range(len(shortest) - length + 1):
            sub = shortest[start:start + length]
            if sub in seen or sum(ch.isalnum() for ch in sub) < 2:
                continue
            seen.add(sub)
            if not all(sub in v for v in lowered):
                continue
            end = start + length
            starts_clean = start == 0 or not (sub[0].isalnum() and shortest[start - 1].isalnum())
            ends_clean = end == len(shortest) or not (sub[-1].isalnum() and shortest[end].isalnum())
            score = (sum(sub in n for n in neg), int(not (starts_clean and ends_clean)), -len(sub), sub)
            if best is None or score < best:
                best = score
    return best[3] if best else None


def _escape_wildcards(value: str) -> str:
    return value.replace("*", "\\*").replace("?", "\\?")


def _field_priority(name: str) -> int:
    low = name.lower()
    return FIELD_PRIORITY.index(low) if low in FIELD_PRIORITY else len(FIELD_PRIORITY)


def _split_fields(positives: list[dict]) -> tuple[list[tuple[str, Any]], list[tuple[str, list[str]]]]:
    """Separate usable fields into (shared exact values) and (varying string values)."""
    shared = set(positives[0])
    for ev in positives[1:]:
        shared &= set(ev)
    exact: list[tuple[str, Any]] = []
    varying: list[tuple[str, list[str]]] = []
    for name in sorted(shared, key=lambda n: (_field_priority(n), n)):
        if name.lower() in VOLATILE_FIELDS:
            continue
        values = [ev[name] for ev in positives]
        if any(isinstance(v, (dict, list)) or v is None for v in values):
            continue
        str_values = [str(v) for v in values]
        if len({s.lower() for s in str_values}) == 1:
            val = values[0]
            if isinstance(val, str) and name.lower().endswith("image") and re.search(r"[\\/]", val):
                # Match the binary name rather than its full path so relocated copies still fire.
                sep = "\\" if "\\" in val else "/"
                exact.append((f"{name}|endswith", sep + re.split(r"[\\/]", val)[-1]))
            else:
                exact.append((name, _escape_wildcards(val) if isinstance(val, str) else val))
        else:
            varying.append((name, str_values))
    return exact, varying


def synthesize_rule(
    positives: list[dict],
    negatives: list[dict],
    description: str,
    title: str | None = None,
    level: str = "medium",
    tags: list[str] | None = None,
    logsource: dict[str, str] | None = None,
) -> str:
    """Derive a conservative rule from labelled samples without an LLM.

    1. Anchor on the highest-priority value every positive shares (usually
       the process image, matched by file name).
    2. Add the best behavioural token from each varying field (command line
       first), chosen against the negatives the selection still matches.
    3. Add further shared values only while they still exclude negatives.

    Volatile per-host fields (PIDs, hostnames, timestamps, hashes) are never
    used, and the selection is capped at four conditions to limit over-fitting.
    """
    max_conditions = 4
    exact, varying = _split_fields(positives)
    selection: dict[str, Any] = {}

    def still_matching() -> list[dict]:
        if not selection:
            return list(negatives)
        probe = compile_rule({"detection": {"selection": selection, "condition": "selection"}})
        return [ev for ev in negatives if probe.matches(ev)]

    if exact:
        key, value = exact.pop(0)
        selection[key] = value

    for name, values in varying:
        if len(selection) >= max_conditions:
            break
        remaining = still_matching()
        neg_values = [str(ev[name]) for ev in remaining if ev.get(name) is not None]
        token = _best_common_substring(values, neg_values)
        if token is None:
            continue
        excludes = sum(token in v.lower() for v in neg_values) < len(remaining)
        if name.lower() == "commandline" or excludes:
            selection[f"{name}|contains"] = _escape_wildcards(token)

    for key, value in exact:
        if len(selection) >= max_conditions or not still_matching():
            break
        before = len(still_matching())
        selection[key] = value
        if len(still_matching()) == before:
            del selection[key]  # adds specificity without excluding anything: leave it out

    if not selection:
        selection = {"CommandLine|contains": "REVIEW_ME"}

    rule = {
        "title": title or f"Synthesized detection: {description.strip().splitlines()[0][:80]}",
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": description.strip() + "\n(Synthesized from labelled samples; review before production use.)",
        "author": "detection-lab synthesizer",
        "logsource": logsource or {"category": "process_creation", "product": "windows"},
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": ["Unknown - synthesized from limited samples; tune before deploying"],
        "level": level,
        "tags": tags or [],
    }
    return yaml.dump(rule, Dumper=_RuleDumper, sort_keys=False, allow_unicode=True, width=120)


class _RuleDumper(yaml.SafeDumper):
    """Emit multi-line strings as ``|`` blocks, the way hand-written Sigma rules look."""


def _str_representer(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_RuleDumper.add_representer(str, _str_representer)
