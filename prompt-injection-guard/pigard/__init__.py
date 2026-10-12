"""pigard: prompt-injection defence and red-teaming toolkit for LLM applications."""

from .canary import CanaryToken, check_leak
from .scanner import Finding, ScanResult, scan

__all__ = ["CanaryToken", "check_leak", "Finding", "ScanResult", "scan"]
__version__ = "0.1.0"
