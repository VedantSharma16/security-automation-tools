"""Command-line entrypoint: parse a log file, run detectors, triage alerts."""

from __future__ import annotations

import argparse
import sys

from .detectors import run_all_detectors
from .knowledge_base import KnowledgeBase
from .parser import parse_file
from .triage import AlertTriageEngine, AnthropicClient


def _build_llm_client(use_llm: bool):
    if not use_llm:
        return None
    try:
        return AnthropicClient()
    except Exception as exc:  # missing package or missing API key
        print(f"[warn] could not initialize Anthropic client ({exc}); falling back to offline triage")
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="log-sentinel: rule-based + LLM-assisted SSH auth log triage"
    )
    parser.add_argument("log_file", help="Path to an SSH auth.log-style file")
    parser.add_argument("--kb", help="Path to a MITRE ATT&CK knowledge base JSON file", default=None)
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use the Anthropic API for alert triage (requires ANTHROPIC_API_KEY)",
    )
    args = parser.parse_args(argv)

    events = parse_file(args.log_file)
    alerts = run_all_detectors(events)

    if not alerts:
        print(f"Parsed {len(events)} events. No alerts triggered.")
        return 0

    kb = KnowledgeBase.load(args.kb)
    engine = AlertTriageEngine(kb, llm_client=_build_llm_client(args.llm))

    print(f"Parsed {len(events)} events, {len(alerts)} alert(s) triggered.\n")
    for alert in alerts:
        print("=" * 70)
        print(f"[{alert.severity.value.upper()}] {alert.rule_id} - {alert.title}")
        print(alert.description)
        print("-" * 70)
        print("Triage:")
        print(engine.triage(alert))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
