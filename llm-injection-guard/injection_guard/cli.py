"""Command-line entry point.

    injection-guard scan [FILE|-] [--source user|retrieved|tool_output] [--llm-judge] [--json]
    injection-guard scan-output [FILE|-] [--canary ID] [--system-prompt FILE] [--json]
    injection-guard eval [--corpus data/corpus.jsonl] [--strict] [--min-f1 0.9] [--json]

Exit codes: ``scan``/``scan-output``: 0 allow, 1 flag, 2 block.
``eval``: 0 if F1 >= --min-f1 (default 0, i.e. always), else 1 - handy as a CI
regression gate when tuning rules.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluate import evaluate, load_corpus
from .guard import SOURCES, Guard, ScanResult

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "data" / "corpus.jsonl"
EXIT = {"allow": 0, "flag": 1, "block": 2}


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _render(result: ScanResult) -> str:
    lines = [f"verdict: {result.verdict.upper()}  score: {result.score:.2f}  source: {result.source}"]
    for s in sorted(result.signals, key=lambda s: -s.weight):
        lines.append(f"  [{s.weight:.2f}] {s.category}/{s.rule} ({s.view}) - {s.evidence}")
        lines.append(f"         {s.meta.owasp} | {s.meta.atlas}")
    if result.judge is not None:
        j = result.judge
        lines.append(f"  LLM judge: injection={j.injection} confidence={j.confidence:.2f} - {j.reason}")
    if not result.signals:
        lines.append("  no signals")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="injection-guard", description="Prompt-injection firewall for LLM / RAG pipelines.")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an input (user prompt, retrieved document, tool output)")
    scan.add_argument("file", nargs="?", default="-")
    scan.add_argument("--source", choices=SOURCES, default="user")
    scan.add_argument("--llm-judge", action="store_true", help="escalate grey-zone scores to Claude (needs ANTHROPIC_API_KEY)")
    scan.add_argument("--judge-model", default=None)
    scan.add_argument("--judge-policy", choices=("grey", "non_block"), default="grey",
                      help="grey: judge only flag-band inputs; non_block: also judge allowed inputs")
    scan.add_argument("--json", action="store_true")

    out = sub.add_parser("scan-output", help="scan a model response for leaks / exfiltration")
    out.add_argument("file", nargs="?", default="-")
    out.add_argument("--canary", help="canary id embedded in the system prompt")
    out.add_argument("--system-prompt", help="file containing the system prompt, for verbatim-leak detection")
    out.add_argument("--json", action="store_true")

    ev = sub.add_parser("eval", help="measure detection quality on a labelled JSONL corpus")
    ev.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ev.add_argument("--strict", action="store_true", help="count only 'block' verdicts as detections")
    ev.add_argument("--min-f1", type=float, default=0.0, help="exit 1 if F1 falls below this")
    ev.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        judge = None
        if args.llm_judge:
            from .judge import DEFAULT_MODEL, ClaudeJudge

            judge = ClaudeJudge(model=args.judge_model or DEFAULT_MODEL)
            if not judge.available:
                print("note: --llm-judge needs the 'anthropic' package and ANTHROPIC_API_KEY; using heuristics only",
                      file=sys.stderr)
                judge = None
        result = Guard(judge=judge, judge_policy=args.judge_policy).scan_input(_read(args.file), args.source)
        print(json.dumps(result.to_dict(), indent=2) if args.json else _render(result))
        return EXIT[result.verdict]

    if args.command == "scan-output":
        system_prompt = Path(args.system_prompt).read_text(encoding="utf-8") if args.system_prompt else None
        result = Guard().scan_output(_read(args.file), canary=args.canary, system_prompt=system_prompt)
        print(json.dumps(result.to_dict(), indent=2) if args.json else _render(result))
        return EXIT[result.verdict]

    report = evaluate(load_corpus(args.corpus), strict=args.strict)
    print(json.dumps(report.to_dict(), indent=2) if args.json else report.render())
    return 0 if report.f1 >= args.min_f1 else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
