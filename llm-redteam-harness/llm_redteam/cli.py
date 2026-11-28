"""Command-line entrypoint.

    llm-redteam run --target vulnerable --target hardened        # offline demo / comparison
    llm-redteam run --target anthropic --i-have-authorization    # real model (needs ANTHROPIC_API_KEY)
    llm-redteam run --target http --url https://staging/chat --canary sk_live_... --i-have-authorization
    llm-redteam guard-eval                                       # precision/recall of the input guard
    llm-redteam scan "Ignore previous instructions..."           # explain a single guard verdict

Exit codes for CI gating: 0 = no successful attack at/above --fail-on,
1 = at least one did, 2 = usage/authorization error.
"""

from __future__ import annotations

import argparse
import json
import sys

from llm_redteam.attacks import DEFAULT_ATTACKS, SEVERITY_ORDER, load_attacks, load_benign, new_marker
from llm_redteam.guard import DEFAULT_THRESHOLD, InjectionGuard, evaluate
from llm_redteam.report import render_comparison, render_console, render_guard_metrics, render_markdown
from llm_redteam.runner import run_campaign
from llm_redteam.targets import AnthropicTarget, HardenedRAGBot, HttpTarget, SimulatedRAGBot

SIMULATED = {"vulnerable", "hardened"}


def _make_target(kind: str, args: argparse.Namespace):
    if kind == "vulnerable":
        return SimulatedRAGBot()
    if kind == "hardened":
        return HardenedRAGBot(guard=InjectionGuard(threshold=args.threshold))
    if kind == "anthropic":
        return AnthropicTarget(model=args.model)
    if kind == "http":
        if not args.url or not args.canary:
            raise SystemExit("--target http requires --url and --canary")
        return HttpTarget(args.url, canary=args.canary, response_field=args.response_field)
    raise SystemExit(f"unknown target {kind!r}")


def cmd_run(args: argparse.Namespace) -> int:
    kinds = args.target or ["vulnerable"]
    if any(k not in SIMULATED for k in kinds) and not args.i_have_authorization:
        print("Refusing to attack a real system without --i-have-authorization. "
              "Only test models/apps you own or are explicitly permitted to assess.", file=sys.stderr)
        return 2

    attacks = load_attacks(args.attacks, categories=args.category)
    if not attacks:
        print("No attacks selected.", file=sys.stderr)
        return 2

    campaigns = []
    for kind in kinds:
        try:
            target = _make_target(kind, args)
        except RuntimeError as exc:
            print(f"Cannot create target {kind!r}: {exc}", file=sys.stderr)
            return 2
        campaigns.append(run_campaign(target, attacks).to_dict())

    if args.json:
        print(json.dumps(campaigns if len(campaigns) > 1 else campaigns[0], indent=2))
    else:
        for c in campaigns:
            print(render_console(c))
            print()
        if len(campaigns) > 1:
            print(render_comparison(campaigns))

    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as fh:
            fh.write("\n---\n\n".join(render_markdown(c) for c in campaigns))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(campaigns, fh, indent=2)

    gate = SEVERITY_ORDER.index(args.fail_on)
    failing = any(
        r["success"] and SEVERITY_ORDER.index(r["severity"]) >= gate
        for c in campaigns for r in c["results"]
    )
    return 1 if failing else 0


def _malicious_corpus(path: str) -> dict[str, str]:
    return {a.id: a.render(new_marker()).injected_text for a in load_attacks(path)}


def cmd_guard_eval(args: argparse.Namespace) -> int:
    malicious = _malicious_corpus(args.attacks)
    benign = load_benign(args.benign) if args.benign else load_benign()
    metrics = [
        evaluate(InjectionGuard(threshold=args.threshold, use_normalization=norm), malicious, benign).to_dict()
        for norm in (False, True)
    ]
    if args.json:
        print(json.dumps(metrics, indent=2))
    else:
        print(render_guard_metrics(metrics))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    result = InjectionGuard(threshold=args.threshold).scan(args.text)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"{'BLOCK' if result.blocked else 'allow'}  score={result.score:.2f}  threshold={args.threshold}")
        for s in result.signals:
            print(f"  signal: {s}")
        for n in result.notes:
            print(f"  note:   {n}")
    return 1 if result.blocked else 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llm-redteam", description="Adversarial testing harness for LLM / RAG applications.")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run an attack campaign against one or more targets.")
    run.add_argument("--target", action="append", choices=["vulnerable", "hardened", "anthropic", "http"],
                     help="Target to attack; repeat to compare targets side by side (default: vulnerable).")
    run.add_argument("--i-have-authorization", action="store_true", help="Required for any non-simulated target.")
    run.add_argument("--attacks", default=str(DEFAULT_ATTACKS), help="Path to an attack corpus JSON file.")
    run.add_argument("--category", action="append", help="Only run attacks in this category (repeatable).")
    run.add_argument("--model", default="claude-sonnet-5-5", help="Model for --target anthropic.")
    run.add_argument("--url", help="Endpoint for --target http.")
    run.add_argument("--canary", help="Secret planted in the HTTP target's system prompt.")
    run.add_argument("--response-field", default="response", help="JSON field holding the HTTP target's reply.")
    run.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="Guard threshold for the hardened target.")
    run.add_argument("--fail-on", choices=SEVERITY_ORDER, default="high", help="Exit 1 if an attack of this severity or worse succeeds.")
    run.add_argument("--json", action="store_true", help="Print JSON instead of a console summary.")
    run.add_argument("--json-out", help="Write full JSON results to this file.")
    run.add_argument("--md-out", help="Write a Markdown report to this file.")
    run.set_defaults(func=cmd_run)

    ge = sub.add_parser("guard-eval", help="Measure the injection guard against the attack and benign corpora.")
    ge.add_argument("--attacks", default=str(DEFAULT_ATTACKS))
    ge.add_argument("--benign", help="Path to a benign prompt corpus JSON file.")
    ge.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ge.add_argument("--json", action="store_true")
    ge.set_defaults(func=cmd_guard_eval)

    sc = sub.add_parser("scan", help="Score a single piece of text with the guard and explain the verdict.")
    sc.add_argument("text")
    sc.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
