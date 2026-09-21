"""Optional LLM-assisted triage for low-confidence findings.

Signature-rule findings (AWS keys, GitHub tokens, PEM private key blocks...)
are high-confidence by construction: the pattern is specific enough that
false positives are rare, so they keep ``confidence="high"`` untouched.

The generic high-entropy "assignment to a random-looking string" rule is the
opposite — it fires just as readily on a genuine leaked secret as on a
UUID, a content hash, or base64 test-fixture data. This module asks an LLM
to break that tie for exactly those findings, or falls back to a small
offline heuristic (keyword match on the variable name) when no API key is
configured — so the tool is always fully usable offline, and
``--llm-triage`` only improves precision on the one ambiguous category.

Only the *redacted* value, the variable/key name, and the file path are ever
sent to the model — never the raw secret. A tool whose job is catching
leaked credentials should not itself exfiltrate the credentials it finds to
a third-party API.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

TRIAGE_CATEGORY = "generic-secret"

SYSTEM_PROMPT = (
    "You are a security engineer triaging possible hardcoded secrets found by "
    "a regex+entropy scanner. For each candidate you are given ONLY a redacted "
    "preview of the value (never the real secret), the variable/key name it was "
    "assigned to, and the file it was found in. Decide if it is a TRUE_POSITIVE "
    "(a real credential/secret that should be rotated and removed) or a "
    "FALSE_POSITIVE (a non-secret random-looking string: UUID, hash, checksum, "
    "test fixture, encoded binary/image data, etc). Respond with ONLY a JSON "
    "array, one object per candidate in the same order, each with keys "
    "'verdict' (TRUE_POSITIVE or FALSE_POSITIVE) and 'reason' (one short "
    "sentence). No prose outside the JSON array."
)

TRUE_POSITIVE_HINTS = (
    "secret", "token", "password", "passwd", "pwd", "apikey", "api_key",
    "access_key", "auth", "credential", "private_key", "client_secret",
)
FALSE_POSITIVE_HINTS = (
    "id", "uuid", "guid", "hash", "checksum", "digest", "sha", "md5",
    "commit", "revision", "session_id", "trace_id", "request_id", "etag",
)


class Triager(Protocol):
    def triage(self, findings: list) -> list: ...


class OfflineHeuristicTriager:
    """Deterministic, dependency-free keyword heuristic. Always available."""

    def triage(self, findings: list) -> list:
        for finding in findings:
            if finding.category != TRIAGE_CATEGORY:
                continue
            key = (finding.context_key or "").lower()
            if any(hint in key for hint in FALSE_POSITIVE_HINTS):
                finding.confidence = "low"
                finding.triage_reason = (
                    f"variable name '{finding.context_key}' suggests a non-secret "
                    "identifier (id/hash/uuid), not a credential"
                )
            elif any(hint in key for hint in TRUE_POSITIVE_HINTS):
                finding.confidence = "high"
                finding.triage_reason = (
                    f"variable name '{finding.context_key}' strongly suggests a credential"
                )
            else:
                finding.confidence = "medium"
                finding.triage_reason = (
                    "high-entropy value with no strong naming signal either way; review manually"
                )
        return findings


class AnthropicTriager:
    """Sends only redacted previews + variable names to Claude for a verdict."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # lazy import: keeps this an optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def triage(self, findings: list) -> list:
        candidates = [f for f in findings if f.category == TRIAGE_CATEGORY]
        if not candidates:
            return findings

        payload = [
            {
                "index": i,
                "file": f.file_path,
                "variable": f.context_key,
                "redacted_value": f.redacted,
            }
            for i, f in enumerate(candidates)
        ]
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": json.dumps(payload)}],
            )
            text = "".join(b.text for b in response.content if b.type == "text")
            verdicts = json.loads(text)
        except Exception as exc:  # network/parse errors fall back, never crash the scan
            print(f"note: LLM triage failed ({exc}); leaving default confidence.", file=sys.stderr)
            return findings

        for verdict, finding in zip(verdicts, candidates):
            is_true_positive = verdict.get("verdict") == "TRUE_POSITIVE"
            finding.confidence = "high" if is_true_positive else "low"
            finding.triage_reason = verdict.get("reason", "").strip() or finding.triage_reason
        return findings


def get_triager(use_llm: bool, model: str = "claude-sonnet-5") -> Triager:
    """Return an AnthropicTriager if requested and usable, else the offline heuristic."""
    if not use_llm:
        return OfflineHeuristicTriager()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "note: --llm-triage requested but ANTHROPIC_API_KEY is not set; "
            "falling back to the offline heuristic triager.",
            file=sys.stderr,
        )
        return OfflineHeuristicTriager()

    try:
        return AnthropicTriager(model=model, api_key=api_key)
    except ImportError:
        print(
            "note: --llm-triage requested but the 'anthropic' package is not installed; "
            "falling back to the offline heuristic triager.",
            file=sys.stderr,
        )
        return OfflineHeuristicTriager()
