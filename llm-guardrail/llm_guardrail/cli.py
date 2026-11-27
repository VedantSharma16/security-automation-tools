"""Command-line interface.

    llm-guardrail scan   --source retrieved --file page.html
    llm-guardrail output --file response.md --canary GRDCNRY-1a2b... --allow-domain example.com
    llm-guardrail eval   data/eval_corpus.jsonl --json eval_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluate import evaluate, format_report, load_corpus
from .guard import Guard, Source, Verdict
from .judge import LLMJudge
from .output_scanner import sanitize_output, scan_output

EXIT_CODES = {Verdict.ALLOW: 0, Verdict.FLAG: 1, Verdict.BLOCK: 2}


def _read_text(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    return sys.stdin.read()


def _cmd_scan(args: argparse.Namespace) -> int:
    judge = LLMJudge(model=args.model) if args.judge else None
    if judge is not None and not judge.is_live:
        print("[warn] --judge requested but no ANTHROPIC_API_KEY / anthropic SDK; using rules only", file=sys.stderr)
    result = Guard(judge=judge).scan(_read_text(args), args.source)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"Verdict: {result.verdict.value.upper()}  (risk {result.risk_score}/100, source={result.source.value})")
        for det in result.detections:
            print(f"  [{det.rule_id}] {det.description}  (+{det.weight}, {det.owasp}, {det.atlas})")
            print(f"      ↳ {det.snippet}")
        if result.judge:
            print(f"  judge: {result.judge['label']} ({result.judge['confidence']:.2f}) — {result.judge['reason']}")
        if result.verdict is Verdict.FLAG:
            print("\nSanitized content to forward:\n" + result.sanitized)
    return EXIT_CODES[result.verdict]


def _cmd_output(args: argparse.Namespace) -> int:
    text = _read_text(args)
    findings = scan_output(text, canaries=args.canary, allowed_domains=set(args.allow_domain), scan_pii=not args.no_pii)
    if args.json:
        print(json.dumps({"findings": [f.to_dict() for f in findings],
                          "sanitized": sanitize_output(text, findings)}, indent=2, ensure_ascii=False))
    else:
        if not findings:
            print("No leaks detected.")
        for f in findings:
            print(f"  [{f.finding_id}] {f.description}: {f.match[:60]}")
        if findings and args.sanitize:
            print("\nSanitized response:\n" + sanitize_output(text, findings))
    worst = max((f.weight for f in findings), default=0)
    return 2 if worst >= 60 else 1 if findings else 0


def _cmd_eval(args: argparse.Namespace) -> int:
    report = evaluate(load_corpus(args.corpus))
    print(format_report(report))
    if args.json:
        Path(args.json).write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nJSON report written to {args.json}")
    if args.min_recall is not None and report.recall < args.min_recall:
        print(f"\nFAIL: recall {report.recall:.3f} below --min-recall {args.min_recall}", file=sys.stderr)
        return 1
    if args.max_fpr is not None and report.false_positive_rate > args.max_fpr:
        print(f"\nFAIL: FPR {report.false_positive_rate:.3f} above --max-fpr {args.max_fpr}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llm-guardrail",
                                     description="Prompt-injection firewall for LLM / RAG / agent pipelines.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_input(p: argparse.ArgumentParser) -> None:
        group = p.add_mutually_exclusive_group()
        group.add_argument("--text", help="text to scan (default: stdin)")
        group.add_argument("--file", help="read text from a file")
        p.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    scan = sub.add_parser("scan", help="scan untrusted input before it reaches the model")
    add_input(scan)
    scan.add_argument("--source", choices=[s.value for s in Source], default="user",
                      help="trust boundary the text crossed (default: user)")
    scan.add_argument("--judge", action="store_true", help="ask an LLM judge about FLAG-band results")
    scan.add_argument("--model", default="claude-opus-5-5", help="model for the LLM judge")
    scan.set_defaults(func=_cmd_scan)

    out = sub.add_parser("output", help="scan a model response for leaks before returning it")
    add_input(out)
    out.add_argument("--canary", action="append", default=[], help="canary token(s) embedded in the system prompt")
    out.add_argument("--allow-domain", action="append", default=[], help="domains allowed in markdown images/links")
    out.add_argument("--no-pii", action="store_true", help="skip PII detection")
    out.add_argument("--sanitize", action="store_true", help="print a redacted version of the response")
    out.set_defaults(func=_cmd_output)

    ev = sub.add_parser("eval", help="measure precision/recall against a labeled corpus")
    ev.add_argument("corpus", help="JSONL file of labeled samples")
    ev.add_argument("--json", help="also write the full report to this path")
    ev.add_argument("--min-recall", type=float, help="exit non-zero if recall falls below this (CI gate)")
    ev.add_argument("--max-fpr", type=float, help="exit non-zero if false-positive rate exceeds this (CI gate)")
    ev.set_defaults(func=_cmd_eval)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
