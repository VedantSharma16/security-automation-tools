"""Gate retrieved documents before they are placed in an LLM context window."""
from __future__ import annotations

from dataclasses import dataclass

from .normalize import normalize
from .scanner import Scanner, ScanResult


@dataclass
class DocDecision:
    doc_id: str
    action: str  # "allow" | "redact" | "quarantine"
    result: ScanResult
    text: str


def sanitize_documents(docs: dict[str, str], scanner: Scanner | None = None) -> list[DocDecision]:
    """Allow clean docs, quarantine blocked ones, and neutralise suspicious ones.

    Suspicious docs are normalized (invisible chars removed) and wrapped in an
    untrusted-data fence so downstream prompts can instruct the model to treat
    the content strictly as data.
    """
    scanner = scanner or Scanner()
    decisions = []
    for doc_id, text in docs.items():
        res = scanner.scan(text)
        if res.verdict == "block":
            decisions.append(DocDecision(doc_id, "quarantine", res, ""))
        elif res.verdict == "suspicious":
            safe = normalize(text).text.replace("```", "'''")
            fenced = f'<untrusted_document id="{doc_id}">\n{safe}\n</untrusted_document>'
            decisions.append(DocDecision(doc_id, "redact", res, fenced))
        else:
            decisions.append(DocDecision(doc_id, "allow", res, text))
    return decisions
