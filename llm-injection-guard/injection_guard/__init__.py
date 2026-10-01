"""llm-injection-guard: defensive tooling against prompt injection."""

from injection_guard.scanner import Finding, ScanResult, scan
from injection_guard.canary import CanaryToken, make_canary, leaked
from injection_guard.spotlight import spotlight

__all__ = ["Finding", "ScanResult", "scan", "CanaryToken", "make_canary", "leaked", "spotlight"]
__version__ = "0.1.0"
