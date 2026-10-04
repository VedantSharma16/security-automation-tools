from __future__ import annotations

import argparse
import sys

from .attacks import ATTACKS
from .report import render_json, render_markdown
from .runner import run_all, summarise
from .targets import build_target


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="redteam", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list the attack corpus")
    r = sub.add_parser("run", help="run the corpus against a target")
    r.add_argument("--target", default="mock-naive",
                   help="mock-naive|mock-partial|mock-hardened|anthropic[:model]")
    r.add_argument("--format", choices=("markdown", "json"), default="markdown")
    r.add_argument("--category", action="append", help="limit to category (repeatable)")
    r.add_argument("--out", help="write report to file instead of stdout")
    r.add_argument("--fail-on-asr", type=float, metavar="RATE",
                   help="exit 1 if attack success rate exceeds RATE (0-1); for CI gating")
    args = p.parse_args(argv)

    if args.cmd == "list":
        for a in ATTACKS:
            print(f"{a.id}  {a.category:<20} {a.owasp:<6} {a.severity:<8} {a.title}")
        return 0

    try:
        target = build_target(args.target)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = run_all(target, categories=set(args.category) if args.category else None)
    render = render_json if args.format == "json" else render_markdown
    out = render(target.name, results)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(out)
    else:
        print(out)
    s = summarise(results)
    if args.fail_on_asr is not None and (s["asr"] > args.fail_on_asr or s["control_failures"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
