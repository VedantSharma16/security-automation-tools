"""CLI: prompt-shield scan FILE|-  |  prompt-shield eval CORPUS"""
from __future__ import annotations

import argparse
import json
import sys

from .evaluate import evaluate
from .scanner import scan

EXIT = {"allow": 0, "review": 1, "block": 2}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="prompt-shield")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan text from a file or stdin ('-')")
    s.add_argument("path")
    s.add_argument("--source", choices=["user", "retrieved", "tool"], default="user")
    s.add_argument("--json", action="store_true")
    e = sub.add_parser("eval", help="evaluate against a labelled JSONL corpus")
    e.add_argument("corpus")
    a = p.parse_args(argv)

    if a.cmd == "eval":
        r = evaluate(a.corpus)
        print(json.dumps(r, indent=2))
        return 0

    text = sys.stdin.read() if a.path == "-" else open(a.path, encoding="utf-8").read()
    res = scan(text, a.source)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(f"verdict={res.verdict} score={res.score} source={res.source}")
        for f in res.findings:
            print(f"  [{f.rule_id}] sev{f.severity} {f.category} ({f.owasp}, {f.via}): {f.excerpt}")
    return EXIT[res.verdict]


if __name__ == "__main__":
    sys.exit(main())
