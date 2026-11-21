"""prompt-injection-guard: a layered prompt-injection firewall for LLM / RAG apps."""

from .output_guard import OutputGuard, make_canary
from .scanner import InjectionScanner, ScanResult, guard_rag_context

__all__ = ["InjectionScanner", "ScanResult", "guard_rag_context", "OutputGuard", "make_canary"]
__version__ = "0.1.0"
