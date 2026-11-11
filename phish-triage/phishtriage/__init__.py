"""phishtriage - explainable phishing email triage for SOC / IR workflows."""

from .analyzer import analyze_bytes, analyze_file

__all__ = ["analyze_bytes", "analyze_file"]
__version__ = "0.1.0"
