"""The agentic triage loop.

In **live** mode (``ANTHROPIC_API_KEY`` set) this drives a real Anthropic
tool-use loop: the model is given the investigation tools from
:mod:`phishing_agent.tools` as function-calling tools, decides for itself
which ones to call and in what order based on what it has already observed,
and finishes by calling a ``submit_verdict`` tool. This is genuine agentic
planning, not a scripted pipeline — a compromised, well-authenticated-looking
email might make the model skip straight to attachment/URL checks, while an
email with nothing obviously wrong might make it check every angle before
concluding.

In **offline** mode (no API key, or the ``anthropic`` package isn't
installed) the agent runs every tool in a fixed, sensible order and derives
a verdict with a deterministic scoring function. This keeps the tool fully
usable and testable without any API key or network access, and produces the
exact same trace/report shape as live mode.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from phishing_agent.email_parser import ParsedEmail
from phishing_agent.tools import (
    DataFeeds,
    SUBMIT_VERDICT_SPEC,
    TOOL_ORDER,
    TOOL_REGISTRY,
    TOOL_SPECS,
)

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_STEPS = 8

SYSTEM_PROMPT = (
    "You are an autonomous SOC analyst agent triaging a single reported email "
    "for phishing. You have a set of investigation tools available (header "
    "analysis, authentication results, URL extraction, URL reputation, "
    "attachment inspection, and language analysis). You do not know in "
    "advance what you'll find, so investigate adaptively: call whichever "
    "tools are most informative given what you've already observed, in "
    "whatever order makes sense, and skip tools that won't add new evidence. "
    "You do not need to call every tool. When you have enough evidence to "
    "reach a conclusion, call `submit_verdict` exactly once with your "
    "verdict (phishing/suspicious/benign), a confidence between 0 and 1, a "
    "short reasoning paragraph, and a list of concrete key_evidence strings "
    "drawn from tool observations. Do not call submit_verdict until you have "
    "called at least one investigation tool."
)


@dataclass
class TraceStep:
    tool: str
    observation: dict

    def to_dict(self) -> dict:
        return {"tool": self.tool, "observation": self.observation}


@dataclass
class AgentResult:
    verdict: str
    confidence: float
    reasoning: str
    key_evidence: list[str]
    trace: list[TraceStep]
    live: bool
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "reasoning": self.reasoning,
            "key_evidence": self.key_evidence,
            "live": self.live,
            "note": self.note,
            "trace": [step.to_dict() for step in self.trace],
        }


def _build_initial_prompt(email: ParsedEmail) -> str:
    return (
        "A user reported the following email as potentially suspicious. "
        "Investigate it using your tools and reach a verdict.\n\n"
        f"From: {email.from_display} <{email.from_addr}>\n"
        f"Subject: {email.subject}\n"
        f"Date: {email.date}\n\n"
        f"Body:\n{email.body_text[:2000]}"
    )


def _offline_score(observations: dict[str, dict]) -> tuple[str, float, list[str]]:
    score = 0
    evidence: list[str] = []

    headers = observations.get("parse_headers", {})
    if headers.get("impersonated_brand"):
        score += 15
        evidence.append(
            f"Display name impersonates '{headers['impersonated_brand']}' but the "
            f"sending domain is '{headers.get('from_domain')}'."
        )
    if headers.get("return_path_mismatches_from"):
        score += 5
        evidence.append(
            f"Return-Path domain ({headers.get('return_path_domain')}) does not "
            f"match the From domain ({headers.get('from_domain')})."
        )

    auth = observations.get("check_authentication", {})
    if not auth.get("header_present"):
        score += 10
        evidence.append("No Authentication-Results header present (SPF/DKIM/DMARC unverifiable).")
    elif auth.get("any_fail"):
        score += 20
        evidence.append(
            f"Authentication failed: spf={auth.get('spf')}, dkim={auth.get('dkim')}, "
            f"dmarc={auth.get('dmarc')}."
        )

    url_rep = observations.get("check_url_reputation", {})
    for finding in url_rep.get("flagged", []):
        if "known_malicious" in finding["flags"]:
            score += 40
            evidence.append(f"URL domain '{finding['domain']}' matches a known-malicious feed entry.")
        if "typosquat" in finding["flags"]:
            score += 25
            target = finding["typosquat_target"]
            evidence.append(
                f"URL domain '{finding['domain']}' is a likely typosquat of "
                f"'{target['brand_domain']}' ({target['brand']}, edit distance {target['edit_distance']})."
            )
        if "punycode_homograph" in finding["flags"]:
            score += 20
            evidence.append(f"URL domain '{finding['domain']}' uses punycode (possible homograph attack).")
        if "ip_literal_url" in finding["flags"]:
            score += 10
            evidence.append(f"URL '{finding['url']}' uses a raw IP address instead of a domain.")

    attachments = observations.get("check_attachments", {})
    for finding in attachments.get("flagged", []):
        if "double_extension" in finding["flags"]:
            score += 25
            evidence.append(f"Attachment '{finding['filename']}' uses a suspicious double extension.")
        elif "risky_extension" in finding["flags"]:
            score += 15
            evidence.append(f"Attachment '{finding['filename']}' has a risky extension.")

    language = observations.get("analyze_language", {})
    hits = language.get("urgency_phrase_hits", [])
    if hits:
        score += min(15, 5 * len(hits))
        evidence.append(f"Urgency/social-engineering language detected: {', '.join(hits)}.")

    score = min(score, 100)
    if score >= 55:
        verdict = "phishing"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "benign"
        if not evidence:
            evidence.append("No phishing indicators found across headers, authentication, URLs, attachments, or language.")

    confidence = min(0.95, 0.35 + score / 130)
    return verdict, confidence, evidence


class PhishingAgent:
    """Runs the investigation loop over a :class:`ParsedEmail`."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_steps: int = DEFAULT_MAX_STEPS,
        feeds: DataFeeds | None = None,
        client: Any = None,
    ):
        self.model = model
        self.max_steps = max_steps
        self.feeds = feeds or DataFeeds.load_default()
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = client
        if self._client is None and self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def investigate(self, email: ParsedEmail) -> AgentResult:
        if self.is_live:
            return self._investigate_live(email)
        return self._investigate_offline(email)

    # -- offline: deterministic full sweep -----------------------------------

    def _investigate_offline(self, email: ParsedEmail) -> AgentResult:
        trace: list[TraceStep] = []
        observations: dict[str, dict] = {}
        for name in TOOL_ORDER:
            obs = TOOL_REGISTRY[name](email, self.feeds)
            observations[name] = obs
            trace.append(TraceStep(tool=name, observation=obs))

        verdict, confidence, evidence = _offline_score(observations)
        reasoning = (
            "Offline heuristic sweep (no ANTHROPIC_API_KEY set): ran every "
            "investigation tool and scored the combined evidence. "
            + (evidence[0] if evidence else "")
        )
        return AgentResult(
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            key_evidence=evidence,
            trace=trace,
            live=False,
            note="Set ANTHROPIC_API_KEY for adaptive, LLM-driven tool selection.",
        )

    # -- live: real Anthropic tool-use loop -----------------------------------

    def _investigate_live(self, email: ParsedEmail) -> AgentResult:
        trace: list[TraceStep] = []
        messages: list[dict] = [{"role": "user", "content": _build_initial_prompt(email)}]
        tools = TOOL_SPECS + [SUBMIT_VERDICT_SPEC]

        for _ in range(self.max_steps):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=tools,
                messages=messages,
            )

            tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
            if not tool_uses:
                break

            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            final: AgentResult | None = None
            for block in tool_uses:
                if block.name == "submit_verdict":
                    inp = block.input
                    final = AgentResult(
                        verdict=inp["verdict"],
                        confidence=float(inp["confidence"]),
                        reasoning=inp["reasoning"],
                        key_evidence=list(inp.get("key_evidence", [])),
                        trace=trace,
                        live=True,
                    )
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": "Verdict recorded.",
                    })
                    continue

                tool_fn = TOOL_REGISTRY.get(block.name)
                if tool_fn is None:
                    observation = {"error": f"unknown tool '{block.name}'"}
                else:
                    observation = tool_fn(email, self.feeds)
                    trace.append(TraceStep(tool=block.name, observation=observation))
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(observation),
                })

            if final is not None:
                return final

            messages.append({"role": "user", "content": tool_results})

        # Safety net: the model didn't call submit_verdict within max_steps.
        observations = {step.tool: step.observation for step in trace}
        verdict, confidence, evidence = _offline_score(observations)
        return AgentResult(
            verdict=verdict,
            confidence=confidence,
            reasoning="Model did not submit a verdict within the step limit; "
            "falling back to deterministic scoring of the tool calls it did make.",
            key_evidence=evidence,
            trace=trace,
            live=True,
            note=f"Forced fallback after {self.max_steps} steps.",
        )
