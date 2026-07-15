"""Command-line entry point: `python -m soc_triage --alerts data/sample_alerts.json`."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional, Sequence

from .knowledge_base import load_techniques
from .models import Alert
from .retriever import TechniqueRetriever
from .triage import TriageEngine

DEFAULT_TECHNIQUES = Path(__file__).resolve().parent.parent / "data" / "attack_techniques.json"


def load_alerts(path: Path) -> List[Alert]:
    data = json.loads(Path(path).read_text())
    return [Alert(**item) for item in data]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RAG-assisted SOC alert triage")
    parser.add_argument("--alerts", required=True, type=Path, help="Path to a JSON file of alerts")
    parser.add_argument(
        "--techniques", type=Path, default=DEFAULT_TECHNIQUES, help="Path to the ATT&CK technique knowledge base JSON"
    )
    parser.add_argument("--top-k", type=int, default=3, help="Number of ATT&CK techniques to retrieve per alert")
    parser.add_argument(
        "--use-claude", action="store_true", help="Use the Claude API narrator instead of the offline rule-based one"
    )
    parser.add_argument("--output", type=Path, help="Optional path to write the full JSON triage report")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = build_parser().parse_args(argv)

    techniques = load_techniques(args.techniques)
    retriever = TechniqueRetriever(techniques)

    narrator = None
    if args.use_claude:
        try:
            from .llm_backend import ClaudeNarrator

            narrator = ClaudeNarrator()
        except Exception as exc:  # missing package or API key
            print(f"warning: falling back to offline narrator ({exc})", file=sys.stderr)

    engine = TriageEngine(retriever, narrator=narrator, top_k=args.top_k)
    alerts = load_alerts(args.alerts)
    results = [engine.triage(alert) for alert in alerts]
    results.sort(key=lambda r: r.risk_score, reverse=True)

    for r in results:
        print(f"[{r.severity.upper():8}] {r.alert_id}  risk={r.risk_score:.2f}  {r.rationale}")

    if args.output:
        args.output.write_text(json.dumps([asdict(r) for r in results], indent=2))
        print(f"\nFull report written to {args.output}")


if __name__ == "__main__":
    main()
