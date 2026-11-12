"""Command-line interface.

    injguard scan  --text "..." | --file path | (stdin)  [--source user|retrieved|tool] [--json] [--judge]
    injguard scan-output --file response.txt [--canary CANARY-...] [--allow-host cdn.example.com] [--json]
    injguard eval data/eval_set.jsonl [--threshold 0.4] [--json]
    injguard canary

Exit codes (useful in CI / pre-commit / pipelines):
    0 allow / safe, 1 review, 2 block / unsafe, 3 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import sys

from .evaluate import evaluate, format_report, load_dataset
from .output_guard import make_canary, scan_output
from .scanner import DEFAULT_BLOCK_THRESHOLD, DEFAULT_REVIEW_THRESHOLD, scan_input

EXIT = {"allow": 0, "review": 1, "block": 2}


def _read_text(args) -> str:
    if getattr(args, "text", None) is not None:
        return args.text
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            return fh.read()
    return sys.stdin.read()


def _cmd_scan(args) -> int:
    text = _read_text(args)
    result = scan_input(text, args.source, args.review_threshold, args.block_threshold)
    final, jv = result.verdict, None
    if args.judge:
        from .judge import LLMJudge, cascade

        judge = LLMJudge(model=args.model)
        if not judge.is_live:
            print("[judge unavailable: set ANTHROPIC_API_KEY and install 'anthropic'; rules-only]", file=sys.stderr)
        final, jv = cascade(result, text, judge, escalate=args.escalate)

    if args.json:
        out = result.to_dict()
        out["final_verdict"] = final
        out["judge"] = None if jv is None else jv.__dict__
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"verdict: {final.upper()}   risk: {result.risk_score:.2f}   source: {result.source}")
        if result.obfuscation:
            print(f"obfuscation: {', '.join(result.obfuscation)}")
        for f in result.findings:
            print(f"  [{f.rule_id}] {f.category} (w={f.weight}) via {f.view}")
            print(f"      {f.description}")
            print(f"      OWASP {f.owasp} | ATLAS {f.atlas}")
            print(f"      match: {f.matched!r}")
        if jv is not None:
            print(f"judge: {jv.label} (confidence {jv.confidence:.2f}) — {jv.reason}")
    return EXIT[final]


def _cmd_scan_output(args) -> int:
    text = _read_text(args)
    result = scan_output(text, canaries=args.canary, allowed_hosts=args.allow_host)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("output: SAFE" if result.safe else f"output: UNSAFE ({len(result.issues)} issue(s))")
        for issue in result.issues:
            print(f"  [{issue.severity}] {issue.kind}: {issue.detail}")
    return 0 if result.safe else 2


def _cmd_eval(args) -> int:
    report = evaluate(load_dataset(args.dataset), threshold=args.threshold)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) if args.json else format_report(report))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="injguard", description="Prompt-injection and LLM output guardrails.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan text before it enters an LLM context")
    src = s.add_mutually_exclusive_group()
    src.add_argument("--text")
    src.add_argument("--file")
    s.add_argument("--source", choices=["user", "retrieved", "tool"], default="user")
    s.add_argument("--review-threshold", type=float, default=DEFAULT_REVIEW_THRESHOLD)
    s.add_argument("--block-threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    s.add_argument("--judge", action="store_true", help="escalate to the LLM judge (needs ANTHROPIC_API_KEY)")
    s.add_argument("--escalate", choices=["review", "non-block"], default="review")
    s.add_argument("--model", default="claude-opus-5-5")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_scan)

    o = sub.add_parser("scan-output", help="scan an LLM response for leaks/exfiltration")
    osrc = o.add_mutually_exclusive_group()
    osrc.add_argument("--text")
    osrc.add_argument("--file")
    o.add_argument("--canary", action="append", default=[], help="canary token(s) planted in the system prompt")
    o.add_argument("--allow-host", action="append", default=[], help="host allowed in images/links")
    o.add_argument("--json", action="store_true")
    o.set_defaults(func=_cmd_scan_output)

    e = sub.add_parser("eval", help="evaluate detection quality on a labeled JSONL dataset")
    e.add_argument("dataset")
    e.add_argument("--threshold", type=float, default=DEFAULT_REVIEW_THRESHOLD)
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=_cmd_eval)

    c = sub.add_parser("canary", help="generate a canary token for a system prompt")
    c.set_defaults(func=lambda a: print(make_canary()) or 0)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in ("scan", "scan-output") and getattr(args, "file", None) is None and args.text is None and sys.stdin.isatty():
        print("error: provide --text, --file, or pipe text on stdin", file=sys.stderr)
        return 3
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
