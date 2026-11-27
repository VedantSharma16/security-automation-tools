"""llm-guardrail: a trust-boundary-aware prompt-injection firewall for LLM,
RAG and agent pipelines."""

from .guard import Guard, ScanResult, Source, Verdict
from .output_scanner import embed_canary, make_canary, sanitize_output, scan_output

__all__ = ["Guard", "ScanResult", "Source", "Verdict", "embed_canary", "make_canary", "sanitize_output", "scan_output"]
__version__ = "0.1.0"
