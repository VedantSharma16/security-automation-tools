"""CLI.

Usage:
    llm-redteam --target mock-vulnerable
    llm-redteam --target anthropic --model claude-haiku-4-5-20251001 --fail-on high
    llm-redteam --target mock-hardened --category jailbreak --markdown-out report.md --json-out report.json
"""

from __future__ import annotations

import argparse
import json
import sys

from llm_redteam.payloads import DEFAULT_CORPUS, SEVERITY_WEIGHT, load_attacks
from llm_redteam.report import to_dict, to_markdown
from llm_redteam.runner import gate_failed, run_attacks
from llm_redteam.targets import get_target


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm-redteam", description="Red-team an LLM application.")
    p.add_argument("--target", default="mock-vulnerable", choices=["mock-vulnerable", "mock-hardened", "anthropic"])
    p.add_argument("--model", help="model id for the anthropic target")
    p.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="attack corpus JSON")
    p.add_argument("--category", action="append", help="restrict to category (repeatable)")
    p.add_argument("--fail-on", choices=list(SEVERITY_WEIGHT), default="high",
                   help="exit 1 if any successful attack is at/above this severity (CI gate)")
    p.add_argument("--json-out")
    p.add_argument("--markdown-out")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    attacks = load_attacks(args.corpus, set(args.category) if args.category else None)
    if not attacks:
        print("No attacks selected.", file=sys.stderr)
        return 2
    target = get_target(args.target, args.model)
    results = run_attacks(target, attacks)
    md = to_markdown(results, target.name)
    print(md)
    if args.markdown_out:
        with open(args.markdown_out, "w", encoding="utf-8") as fh:
            fh.write(md)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(to_dict(results, target.name), fh, indent=2)
    return 1 if gate_failed(results, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
