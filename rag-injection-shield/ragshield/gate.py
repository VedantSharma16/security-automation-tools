"""Retrieval gate: filter/sanitise RAG chunks before prompt assembly."""
from __future__ import annotations

from dataclasses import dataclass

from .sanitizer import sanitize, wrap_untrusted
from .scanner import ScanResult, scan_text


@dataclass
class GateDecision:
    chunk_id: str
    action: str  # pass | sanitized | dropped
    result: ScanResult
    text: str | None  # text to place in the prompt (None if dropped)


def gate_chunks(chunks: dict[str, str] | list[tuple[str, str]],
                quarantine_policy: str = "sanitize") -> list[GateDecision]:
    """Scan each chunk. allow -> pass, quarantine -> sanitize (or drop), block -> drop.

    quarantine_policy: "sanitize" or "drop".
    """
    if quarantine_policy not in ("sanitize", "drop"):
        raise ValueError("quarantine_policy must be 'sanitize' or 'drop'")
    items = chunks.items() if isinstance(chunks, dict) else chunks
    decisions = []
    for cid, text in items:
        res = scan_text(text)
        if res.verdict == "block":
            decisions.append(GateDecision(cid, "dropped", res, None))
        elif res.verdict == "quarantine":
            if quarantine_policy == "drop":
                decisions.append(GateDecision(cid, "dropped", res, None))
            else:
                decisions.append(GateDecision(cid, "sanitized", res, wrap_untrusted(sanitize(text, res), cid)))
        else:
            decisions.append(GateDecision(cid, "pass", res, wrap_untrusted(text, cid)))
    return decisions
