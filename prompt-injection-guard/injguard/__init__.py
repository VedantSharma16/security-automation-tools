"""prompt-injection-guard: input/output guardrails for LLM applications."""

from .output_guard import embed_canary, make_canary, scan_output
from .scanner import scan_input

__all__ = ["scan_input", "scan_output", "make_canary", "embed_canary"]
__version__ = "0.1.0"
