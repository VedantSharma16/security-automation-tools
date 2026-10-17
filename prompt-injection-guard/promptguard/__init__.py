"""promptguard: heuristic prompt-injection detection for untrusted LLM input."""

from .canary import Canary
from .sanitizer import sanitize_chunks, wrap_untrusted
from .scanner import Finding, ScanResult, scan

__all__ = ["Canary", "Finding", "ScanResult", "scan", "sanitize_chunks", "wrap_untrusted"]
__version__ = "0.1.0"
