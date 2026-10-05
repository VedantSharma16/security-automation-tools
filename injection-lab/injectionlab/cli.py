"""Command line interface."""

from __future__ import annotations

import argparse
import sys

from . import harness
from .guard import scan
from .targets import TARGETS


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="injection-lab", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the payload corpus against a target")
    r.add_argument("--target", choices=sorted(TARGETS), default="vulnerable")
    r.add_argument("--payloads", help="custom payload JSON file")
    r.add_argument("--format", choices=["markdown", "json"], default="markdown")
    r.add_argument("--fail-above", type=float, metavar="RATE",
                   help="exit 1 if attack success rate exceeds RATE (CI gate)")

    s = sub.add_parser("scan", help="score a single input with the guard")
    s.add_argument("text")

    args = ap.parse_args(argv)

    if args.cmd == "scan":
        res = scan(args.text)
        print(f"score={res.score} blocked={res.blocked} matched={','.join(res.matched) or '-'}")
        return 1 if res.blocked else 0

    results = harness.run(TARGETS[args.target](), harness.load_payloads(args.payloads))
    out = harness.to_json(results) if args.format == "json" else harness.to_markdown(
        results, f"Prompt-injection assessment: {args.target}")
    print(out)
    if args.fail_above is not None and harness.summarize(results)["attack_success_rate"] > args.fail_above:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
