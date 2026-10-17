"""Apply scan verdicts to RAG context and wrap what survives as untrusted data."""

from __future__ import annotations

from .scanner import ScanResult, scan


def wrap_untrusted(text: str, source: str = "retrieved") -> str:
    """Fence data so the prompt can instruct the model to treat it as content only."""
    text = text.replace("</untrusted_data>", "<\\/untrusted_data>")
    return f'<untrusted_data source="{source}">\n{text}\n</untrusted_data>'


def sanitize_chunks(chunks: list[tuple[str, str]], block_on: str = "block"):
    """chunks: (source, text) pairs. Returns (safe_wrapped_chunks, quarantined_results).

    block_on="review" also quarantines borderline chunks (stricter).
    """
    drop = {"block"} if block_on == "block" else {"block", "review"}
    safe: list[str] = []
    quarantined: list[ScanResult] = []
    for source, text in chunks:
        result = scan(text, source)
        if result.verdict in drop:
            quarantined.append(result)
        else:
            safe.append(wrap_untrusted(text, source))
    return safe, quarantined
