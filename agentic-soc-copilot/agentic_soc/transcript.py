"""Data model for an agent investigation: the step-by-step trace and verdict.

Recording every tool call and observation (not just the final answer) is
what makes an automated triage decision auditable -- a hard requirement for
using AI in an incident-response workflow, where an analyst or auditor must
be able to reconstruct *why* the agent concluded what it did.
"""

from __future__ import annotations

from dataclasses import dataclass, field

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_BENIGN = "benign"
VALID_VERDICTS = {VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_BENIGN}


@dataclass
class AgentStep:
    thought: str
    tool: str
    tool_input: dict
    observation: dict

    def to_dict(self) -> dict:
        return {
            "thought": self.thought,
            "tool": self.tool,
            "tool_input": self.tool_input,
            "observation": self.observation,
        }


@dataclass
class Verdict:
    verdict: str
    confidence: float
    reasoning: str
    recommended_actions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.verdict not in VALID_VERDICTS:
            raise ValueError(f"Invalid verdict {self.verdict!r}; expected one of {sorted(VALID_VERDICTS)}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "recommended_actions": list(self.recommended_actions),
        }


@dataclass
class AgentTranscript:
    alert_text: str
    steps: list[AgentStep]
    verdict: Verdict
    llm_backed: bool

    @property
    def steps_used(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict:
        return {
            "alert_text": self.alert_text,
            "steps": [s.to_dict() for s in self.steps],
            "steps_used": self.steps_used,
            "verdict": self.verdict.to_dict(),
            "llm_backed": self.llm_backed,
        }
