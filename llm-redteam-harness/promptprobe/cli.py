"""Command line interface: ``promptprobe --target vulnerable --fail-above 20``."""

from __future__ import annotations

import argparse
import sys

from . import guard, report
from .attacks import build_corpus
from .harness import run
from .targets import get_target


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="promptprobe", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the attack corpus against a target")
    r.add_argument("--target", default="vulnerable",
                   help="vulnerable | hardened | vulnerable+guard | anthropic[:model]")
    r.add_argument("--format", choices=["markdown", "json"], default="markdown")
    r.add_argument("--fail-above", type=int, metavar="SCORE",
                   help="exit 1 if risk score exceeds SCORE (CI gate)")

    c = sub.add_parser("check", help="run the input guard on a string")
    c.add_argument("text")

    a = p.parse_args(argv)
    if a.cmd == "check":
        v = guard.inspect(a.text)
        print(f"blocked={v.blocked} score={v.score} rules={','.join(v.rules) or '-'}")
        return 1 if v.blocked else 0

    summary = run(get_target(a.target), build_corpus())
    print(report.to_json(summary) if a.format == "json" else report.to_markdown(summary))
    if a.fail_above is not None and summary.risk_score > a.fail_above:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
