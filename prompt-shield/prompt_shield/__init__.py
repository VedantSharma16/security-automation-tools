"""prompt-shield: heuristic prompt-injection detection and output guarding."""
from .scanner import Finding, ScanResult, scan
from .output_guard import OutputFinding, guard_output, make_canary

__all__ = ["Finding", "ScanResult", "scan", "OutputFinding", "guard_output", "make_canary"]
