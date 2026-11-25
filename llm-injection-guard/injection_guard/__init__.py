"""llm-injection-guard: a defence-in-depth prompt-injection firewall for LLM, RAG and agent pipelines."""

from .guard import Guard, JudgeVerdict, SanitizedContext, ScanResult, make_canary, with_canary

__all__ = ["Guard", "JudgeVerdict", "SanitizedContext", "ScanResult", "make_canary", "with_canary"]
__version__ = "0.1.0"
