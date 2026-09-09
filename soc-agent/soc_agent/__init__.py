"""soc-agent: an autonomous tool-calling SOC triage agent."""

from .agent import SocAgent
from .tools import ToolContext, Verdict

__all__ = ["SocAgent", "ToolContext", "Verdict"]
