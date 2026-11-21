"""Command-line entry point: `pi-guard {scan,scan-rag,scan-output,eval,train,canary}`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .classifier import DEFAULT_MODEL_PATH, train_from_corpus
from .evaluate import evaluate, format_report
from .judge import LLMJudge
from .output_guard import OutputGuard, make_canary
from .scanner import InjectionScanner, guard_rag_context

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
EXIT_ALLOW, EXIT_REVIEW, EXIT_BLOCK = 0, 1, 2


def _read_input(args) -> str:
    if args.text is not None:
        return args.text
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    return sys.stdin.read()


def _print_scan(result, as_json: bool, judge_decision=None) -> None:
    if as_json:
        payload = result.to_dict()
        if judge_decision is not None:
            payload["judge"] = vars(judge_decision)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    print(f"verdict: {result.verdict.upper()}   risk score: {result.score}/100   source: {result.source}")
    for f in result.findings:
        print(f"  [{f.rule_id}] {f.name}  (w={f.weight}, {f.owasp}, ATLAS {f.atlas}, via {f.via})")
        print(f"      evidence: {f.evidence}")
    if judge_decision is not None:
        print(f"  LLM judge: injection={judge_decision.injection} "
              f"confidence={judge_decision.confidence:.2f} — {judge_decision.reason}")


def cmd_scan(args) -> int:
    scanner = InjectionScanner(use_classifier=not args.no_ml)
    text = _read_input(args)
    result = scanner.scan(text, source=args.source)
    decision = None
    if args.judge:
        judge = LLMJudge()
        if not judge.is_live:
            print("note: --judge requested but ANTHROPIC_API_KEY / anthropic SDK unavailable; "
                  "review verdicts left for a human.", file=sys.stderr)
        result, decision = judge.adjudicate(text, result)
    _print_scan(result, args.json, decision)
    return {"allow": EXIT_ALLOW, "review": EXIT_REVIEW, "block": EXIT_BLOCK}[result.verdict]


def cmd_scan_rag(args) -> int:
    chunks = [c.strip() for c in Path(args.file).read_text(encoding="utf-8").split(args.delimiter) if c.strip()]
    guarded = guard_rag_context(chunks, InjectionScanner(use_classifier=not args.no_ml),
                                quarantine_at=args.quarantine_at)
    if args.json:
        print(json.dumps({
            "total_chunks": len(chunks),
            "safe_chunks": len(guarded.safe_chunks),
            "quarantined": [{"index": i, **r.to_dict()} for i, r in guarded.quarantined],
        }, indent=2, ensure_ascii=False))
    else:
        print(f"{len(guarded.safe_chunks)}/{len(chunks)} chunks passed; {len(guarded.quarantined)} quarantined")
        for i, r in guarded.quarantined:
            rules = ", ".join(f.rule_id for f in r.findings)
            print(f"  chunk #{i}: {r.verdict.upper()} score={r.score} [{rules}]  {chunks[i][:70]!r}")
    return EXIT_BLOCK if guarded.quarantined else EXIT_ALLOW


def cmd_scan_output(args) -> int:
    system_prompt = Path(args.system_prompt).read_text(encoding="utf-8") if args.system_prompt else None
    guard = OutputGuard(canaries=args.canary, system_prompt=system_prompt,
                        allowed_domains=args.allow_domain, check_pii=not args.no_pii)
    result = guard.scan(_read_input(args))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"leak detected: {'YES' if result.leaked else 'no'}   worst severity: {result.worst_severity}")
        for f in result.findings:
            print(f"  [{f.severity.upper():<8}] {f.kind}: {f.detail}")
    return EXIT_BLOCK if result.leaked else EXIT_ALLOW


def cmd_eval(args) -> int:
    scanner = InjectionScanner(use_classifier=not args.no_ml)
    reports = {Path(p).stem: evaluate(p, scanner) for p in args.corpus}
    if args.json:
        print(json.dumps({k: v.to_dict() for k, v in reports.items()}, indent=2, ensure_ascii=False))
    else:
        print("\n\n".join(format_report(k, v) for k, v in reports.items()))
    return EXIT_ALLOW


def cmd_train(args) -> int:
    model = train_from_corpus(args.corpus, max_fpr=args.max_fpr)
    model.save(args.out)
    print(f"trained on {sum(model.doc_counts.values())} samples "
          f"({model.doc_counts['malicious']} malicious / {model.doc_counts['benign']} benign); "
          f"LOO-calibrated log-odds threshold = {model.threshold:.3f} -> {args.out}")
    return EXIT_ALLOW


def cmd_canary(_args) -> int:
    print(make_canary())
    return EXIT_ALLOW


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pi-guard", description=(
        "Prompt-injection firewall for LLM apps: scan inputs and RAG chunks, check outputs for leaks."))
    sub = parser.add_subparsers(dest="command", required=True)

    def add_input(p):
        group = p.add_mutually_exclusive_group()
        group.add_argument("--text", help="text to scan (default: read stdin)")
        group.add_argument("--file", help="file to scan")
        p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("scan", help="scan a user prompt or document for injection")
    add_input(p)
    p.add_argument("--source", choices=["user", "retrieved"], default="user",
                   help="'retrieved' = third-party content (RAG/web/email); scored more strictly")
    p.add_argument("--no-ml", action="store_true", help="rules only, disable the NB classifier")
    p.add_argument("--judge", action="store_true", help="resolve REVIEW verdicts with an LLM judge")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("scan-rag", help="filter a file of retrieved chunks before prompt assembly")
    p.add_argument("--file", required=True)
    p.add_argument("--delimiter", default="\n---\n", help="chunk separator (default: a line of ---)")
    p.add_argument("--quarantine-at", choices=["review", "block"], default="review")
    p.add_argument("--no-ml", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan_rag)

    p = sub.add_parser("scan-output", help="check a model response for leaks/exfiltration")
    add_input(p)
    p.add_argument("--canary", action="append", default=[], help="canary token planted in the system prompt")
    p.add_argument("--system-prompt", help="file containing the real system prompt (overlap check)")
    p.add_argument("--allow-domain", action="append", default=[], help="domain allowed in rendered links")
    p.add_argument("--no-pii", action="store_true", help="skip PII checks")
    p.set_defaults(func=cmd_scan_output)

    p = sub.add_parser("eval", help="precision/recall against labelled corpora")
    p.add_argument("corpus", nargs="*", default=[str(DATA_DIR / "eval_corpus.jsonl"),
                                                  str(DATA_DIR / "holdout_corpus.jsonl")])
    p.add_argument("--no-ml", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("train", help="retrain the NB classifier and recalibrate its threshold")
    p.add_argument("--corpus", default=str(DATA_DIR / "eval_corpus.jsonl"))
    p.add_argument("--out", default=str(DEFAULT_MODEL_PATH))
    p.add_argument("--max-fpr", type=float, default=0.05)
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("canary", help="generate a canary token for your system prompt")
    p.set_defaults(func=cmd_canary)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
