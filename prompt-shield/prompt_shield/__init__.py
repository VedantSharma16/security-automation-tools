"""prompt-shield: layered prompt-injection detection for LLM applications."""

from .detector import Finding, Verdict, scan

__all__ = ["Finding", "Verdict", "scan"]
__version__ = "0.1.0"
