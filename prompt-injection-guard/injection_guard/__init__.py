"""Layered prompt-injection defense for LLM / RAG applications."""

from .detector import Detector, ScanResult, scan
from .output_guard import canary_leaked, inspect_response, make_canary
from .spotlight import build_guarded_prompt, datamark

__all__ = [
    "Detector", "ScanResult", "scan",
    "build_guarded_prompt", "datamark",
    "make_canary", "canary_leaked", "inspect_response",
]
__version__ = "0.1.0"
