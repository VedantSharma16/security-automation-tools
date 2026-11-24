"""prompt_firewall - detect and neutralise prompt injection in LLM pipelines."""

from .output_guard import embed_canary, make_canary, scan_output
from .scanner import Policy, ScanResult, Scanner, neutralize, sanitize_text, spotlight

__all__ = [
    "Policy",
    "ScanResult",
    "Scanner",
    "embed_canary",
    "make_canary",
    "neutralize",
    "sanitize_text",
    "scan_output",
    "spotlight",
]
__version__ = "0.1.0"
