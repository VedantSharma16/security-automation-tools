"""CLI. Exit code 1 when the resistance score is below --fail-under, so the
harness can gate CI for LLM apps."""
from __future__ import annotations

import argparse
import json
import sys

from .attacks import ATTACKS
from .mutators import MUTATORS, expand
from .report import render_markdown
from .runner import run_suite, summarize, to_dict
from .targets import BUILTIN_TARGETS, AnthropicTarget


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llmredteam", description=__doc__)
    p.add_argument("--target", default="vulnerable", choices=[*BUILTIN_TARGETS, "anthropic"])
    p.add_argument("--model", default="claude-haiku-4-5-20251001", help="model for --target anthropic")
    p.add_argument("--mutations", nargs="*", default=[], choices=list(MUTATORS),
                   help="also run obfuscated variants of every attack")
    p.add_argument("--category", action="append", help="limit to category (repeatable)")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--fail-under", type=float, default=None, help="exit 1 if resistance score < N")
    p.add_argument("--list", action="store_true", help="list attacks and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        for a in ATTACKS:
            print(f"{a.id}\t{a.category}\t{a.severity}\t{a.owasp}\t{a.name}")
        return 0
    attacks = [a for a in ATTACKS if not args.category or a.category in args.category]
    attacks = expand(attacks, args.mutations)
    target = AnthropicTarget(args.model) if args.target == "anthropic" else BUILTIN_TARGETS[args.target]
    results = run_suite(target, attacks)
    if args.format == "json":
        print(json.dumps(to_dict(results), indent=2))
    else:
        print(render_markdown(results, args.target), end="")
    if args.fail_under is not None and summarize(results)["resistance_score"] < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
