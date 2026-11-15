"""Command-line interface.

    prompt-firewall scan "Ignore previous instructions and ..."
    prompt-firewall scan --file page.txt --source retrieved
    prompt-firewall scan-output --file reply.txt --system-prompt-file sys.txt --allow-domain example.com
    prompt-firewall mutate "ignore previous instructions" --technique all
    prompt-firewall eval [--json] [--no-mutations]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluate import DEFAULT_EVAL_PATH, format_report, run_ablation
from .firewall import Firewall
from .judge import LLMJudge
from .redteam import MUTATORS, mutate

EXIT_CODES = {"allow": 0, "flag": 1, "block": 2}


def _read_text(args: argparse.Namespace) -> str:
    if getattr(args, "file", None):
        return Path(args.file).read_text(encoding="utf-8")
    if getattr(args, "text", None):
        return args.text
    return sys.stdin.read()


def _cmd_scan(args: argparse.Namespace) -> int:
    judge = LLMJudge(model=args.model) if args.llm_judge else None
    verdict = Firewall(judge=judge).scan_input(_read_text(args), source=args.source)
    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"action: {verdict.action.upper()}  score={verdict.score:.2f} "
              f"(rules={verdict.rule_score:.2f}, ml={verdict.ml_score:.2f}, source={verdict.source})")
        for hit in verdict.hits:
            print(f"  [{hit.rule_id}] {hit.category:<20} {hit.atlas:<14} w={hit.weight:.2f} via {hit.view}: {hit.evidence!r}")
        if verdict.obfuscation:
            print(f"  obfuscation: {', '.join(verdict.obfuscation)}")
        if verdict.ml_features:
            print("  ml evidence: " + ", ".join(t for t, _ in verdict.ml_features))
        if verdict.judge:
            print(f"  llm judge: {verdict.judge}")
    return EXIT_CODES[verdict.action]


def _cmd_scan_output(args: argparse.Namespace) -> int:
    system_prompt = Path(args.system_prompt_file).read_text(encoding="utf-8") if args.system_prompt_file else None
    verdict = Firewall(model=None, use_ml=False).scan_output(
        _read_text(args), canary=args.canary, system_prompt=system_prompt, allowed_domains=set(args.allow_domain or [])
    )
    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"action: {verdict.action.upper()}  ({len(verdict.findings)} finding(s))")
        for f in verdict.findings:
            print(f"  [{f.severity}] {f.kind}: {f.detail}")
        if verdict.findings:
            print("\n--- redacted output ---\n" + verdict.redacted_text)
    return EXIT_CODES[verdict.action]


def _cmd_mutate(args: argparse.Namespace) -> int:
    techniques = sorted(MUTATORS) if args.technique == "all" else [args.technique]
    for i, t in enumerate(techniques):
        variant = mutate(args.text, t, seed=i)
        print(f"{t}: {variant.encode('unicode_escape').decode() if args.escape else variant}")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    results = run_ablation(args.dataset, with_mutations=not args.no_mutations)
    if args.json:
        print(json.dumps({k: m.summary() for k, m in results.items()}, indent=2))
    else:
        print(format_report(results))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prompt-firewall", description="Prompt-injection firewall for LLM applications.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan an input (user prompt or retrieved document)")
    s.add_argument("text", nargs="?")
    s.add_argument("--file")
    s.add_argument("--source", choices=["user", "retrieved"], default="user")
    s.add_argument("--llm-judge", action="store_true", help="escalate grey-zone inputs to an LLM (needs ANTHROPIC_API_KEY)")
    s.add_argument("--model", default="claude-opus-5-5")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_scan)

    o = sub.add_parser("scan-output", help="scan model output for leaks and exfiltration")
    o.add_argument("text", nargs="?")
    o.add_argument("--file")
    o.add_argument("--canary")
    o.add_argument("--system-prompt-file")
    o.add_argument("--allow-domain", action="append", help="domain allowed in rendered links/images (repeatable)")
    o.add_argument("--json", action="store_true")
    o.set_defaults(func=_cmd_scan_output)

    m = sub.add_parser("mutate", help="generate obfuscated red-team variants of a payload")
    m.add_argument("text")
    m.add_argument("--technique", default="all", choices=["all", *sorted(MUTATORS)])
    m.add_argument("--escape", action="store_true", help="show invisible characters as escapes")
    m.set_defaults(func=_cmd_mutate)

    e = sub.add_parser("eval", help="run the benchmark and ablation")
    e.add_argument("--dataset", default=str(DEFAULT_EVAL_PATH))
    e.add_argument("--no-mutations", action="store_true")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=_cmd_eval)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
