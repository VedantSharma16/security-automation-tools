"""promptshield: offline guardrail and red-team harness for LLM applications."""
from .models import Finding, ScanResult
from .scanner import scan
from .canary import Canary

__all__ = ["Finding", "ScanResult", "scan", "Canary"]
__version__ = "0.1.0"
