"""ragshield: detect indirect prompt injection in documents before they reach an LLM."""

from .scanner import Finding, ScanResult, scan_text
from .gate import GateDecision, gate_chunks
from .sanitizer import sanitize, wrap_untrusted

__all__ = [
    "Finding", "ScanResult", "scan_text",
    "GateDecision", "gate_chunks",
    "sanitize", "wrap_untrusted",
]
__version__ = "0.1.0"
