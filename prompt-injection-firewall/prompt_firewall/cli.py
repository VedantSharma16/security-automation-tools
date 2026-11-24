"""Command-line interface.

    prompt-firewall scan "ignore previous instructions"           # direct prompt
    prompt-firewall scan --file page.html --source retrieved      # RAG chunk
    prompt-firewall scan-output --file reply.txt --canary PIF-...  # model output
    prompt-firewall eval                                          # benchmark rules
    prompt-firewall canary                                        # mint a canary

Exit codes for ``scan``: 0 allow, 1 sanitize, 2 block (usable as a CI or
pipeline gate). ``scan-output``: 0 clean, 2 blocked. ``eval``: 0 if the F1
gate passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluate import evaluate, load_corpus
from .judge import LLMJudge
from .output_guard import make_canary, scan_output
from .rules import load_rules
from .scanner import SOURCES, Policy, Scanner, sanitize_text

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "data" / "eval_corpus.jsonl"
EXIT_BY_VERDICT = {"allow": 0, "sanitize": 1, "block": 2}


def _read_input(args) -> str:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    if args.text is not None:
        return args.text
    return sys.stdin.read()


def _build_scanner(args) -> Scanner:
    judge = None
    if getattr(args, "llm_judge", False):
        judge = LLMJudge()
        if not judge.available:
            print("warning: --llm-judge requested but ANTHROPIC_API_KEY/anthropic SDK unavailable; "
                  "using rules only", file=sys.stderr)
            judge = None
    return Scanner(
        rules=load_rules(args.rules) if args.rules else None,
        policy=Policy(sanitize_at=args.sanitize_at, block_at=args.block_at),
        judge=judge,
    )


def _render_scan(result, text: str) -> str:
    lines = [f"Verdict: {result.verdict.upper()}  (score {result.score}/100, source={result.source})"]
    if not result.findings:
        lines.append("No findings.")
    for f in result.findings:
        via = f" via {f.via}" if f.via != "text" else ""
        lines.append(f"  [{f.severity.upper():8}] {f.rule_id} {f.name}{via}")
        lines.append(f"             {f.owasp} | ATLAS {f.atlas}")
        lines.append(f"             evidence: {f.evidence}")
    if result.judge:
        j = result.judge
        lines.append(f"LLM judge: {j['label']} ({j['confidence']:.2f}) - {j['rationale']}")
    if result.sanitized is not None:
        lines.append("")
        lines.append("Sanitized text:")
        lines.append(result.sanitized)
    return "\n".join(lines)


def cmd_scan(args) -> int:
    text = _read_input(args)
    scanner = _build_scanner(args)
    result = scanner.scan(text, source=args.source)
    if result.sanitized is not None and args.mode != "delimit":
        result.sanitized = sanitize_text(text, source=args.source, mode=args.mode)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) if args.json else _render_scan(result, text))
    return EXIT_BY_VERDICT[result.verdict]


def cmd_scan_output(args) -> int:
    text = _read_input(args)
    result = scan_output(text, canary=args.canary)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print("BLOCKED" if result.blocked else "CLEAN")
        for f in result.findings:
            print(f"  - {f.kind}: {f.detail}")
        if result.blocked:
            print("\nRedacted output:\n" + result.redacted)
    return 2 if result.blocked else 0


def cmd_eval(args) -> int:
    samples = load_corpus(args.corpus)
    report = evaluate(samples, _build_scanner(args))
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(report.render())
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    if report.f1 < args.min_f1:
        print(f"\nF1 {report.f1:.3f} is below the --min-f1 gate of {args.min_f1}", file=sys.stderr)
        return 1
    return 0


def cmd_canary(args) -> int:
    print(make_canary())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prompt-firewall",
        description="Detect and neutralise prompt-injection attacks in LLM inputs, RAG content and outputs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, input_=True):
        if input_:
            p.add_argument("text", nargs="?", help="text to scan (default: stdin)")
            p.add_argument("--file", help="read input from a file")
        p.add_argument("--json", action="store_true", help="emit JSON")

    def policy_opts(p):
        p.add_argument("--rules", help="path to a custom rules.json")
        p.add_argument("--sanitize-at", type=int, default=30)
        p.add_argument("--block-at", type=int, default=60)
        p.add_argument("--llm-judge", action="store_true",
                       help="escalate grey-zone inputs to an LLM classifier (needs ANTHROPIC_API_KEY)")

    p = sub.add_parser("scan", help="scan an input prompt / retrieved document / tool output")
    common(p)
    policy_opts(p)
    p.add_argument("--source", choices=SOURCES, default="user")
    p.add_argument("--mode", choices=("delimit", "datamark"), default="delimit",
                   help="spotlighting mode used when sanitising untrusted content")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("scan-output", help="scan a model response for leaks")
    common(p)
    p.add_argument("--canary", help="canary token embedded in the system prompt")
    p.set_defaults(func=cmd_scan_output)

    p = sub.add_parser("eval", help="benchmark the rule set against a labelled corpus")
    common(p, input_=False)
    policy_opts(p)
    p.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    p.add_argument("--json-out", help="also write the JSON report to this path")
    p.add_argument("--min-f1", type=float, default=0.0, help="fail (exit 1) if F1 is below this")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("canary", help="generate a fresh canary token")
    p.set_defaults(func=cmd_canary)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
