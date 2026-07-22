"""ir-agent: an agentic incident-response investigation loop.

See README.md for the pipeline overview and architecture rationale.
"""

from .agent import AgentResult, IncidentResponseAgent

__all__ = ["AgentResult", "IncidentResponseAgent"]
