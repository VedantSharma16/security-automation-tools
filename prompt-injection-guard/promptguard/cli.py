"""CLI: promptguard scan <files...> | eval <corpus.jsonl>."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluate import evaluate
from .scanner import scan

_ORDER = {"allow": 0, "review": 1, "block": 2}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="promptguard", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan files (or '-' for stdin)")
    s.add_argument("paths", nargs="+")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on", choices=["review", "block"], default="block")
    e = sub.add_parser("eval", help="precision/recall on a labelled JSONL corpus")
    e.add_argument("corpus", type=Path)
    e.add_argument("--flag", choices=["review", "block"], default="review")
    args = p.parse_args(argv)

    if args.cmd == "eval":
        print(json.dumps(evaluate(args.corpus, args.flag), indent=2))
        return 0

    results = []
    for path in args.paths:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(errors="replace")
        results.append(scan(text, "stdin" if path == "-" else path))
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print(f"[{r.verdict.upper():6}] score={r.score:<3} {r.source}")
            for f in r.findings:
                tag = " (obfuscated)" if f.obfuscated else ""
                print(f"    {f.rule_id} {f.category}: {f.description}{tag}\n        > {f.evidence!r}")
    threshold = _ORDER[args.fail_on]
    return 1 if any(_ORDER[r.verdict] >= threshold for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
