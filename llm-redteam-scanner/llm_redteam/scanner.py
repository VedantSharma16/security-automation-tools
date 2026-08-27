"""Orchestrates running the attack library against a target and judging results."""

from __future__ import annotations

from dataclasses import dataclass

from llm_redteam.attacks import ATTACKS, INDIRECT, Attack
from llm_redteam.judge import ResponseJudge, Verdict

BENIGN_CARRIER_MESSAGE = (
    "Hi, can you help me understand my recent order? Here's some context "
    "from our knowledge base:"
)


@dataclass
class ScanFinding:
    attack: Attack
    response: str
    verdict: Verdict


def run_attack(target, attack: Attack, judge: ResponseJudge) -> ScanFinding:
    if attack.delivery == INDIRECT:
        response = target.respond(BENIGN_CARRIER_MESSAGE, retrieved_context=attack.payload)
    else:
        response = target.respond(attack.payload)
    verdict = judge.evaluate(attack, target, response)
    return ScanFinding(attack=attack, response=response, verdict=verdict)


def run_scan(
    target,
    attacks: tuple[Attack, ...] = ATTACKS,
    judge: ResponseJudge | None = None,
) -> list[ScanFinding]:
    judge = judge or ResponseJudge()
    return [run_attack(target, attack, judge) for attack in attacks]
