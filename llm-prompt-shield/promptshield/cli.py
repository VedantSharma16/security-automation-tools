from __future__ import annotations

import argparse
import json
import sys

from .canary import Canary
from .redteam import evaluate, load_corpus
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="promptshield", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan text (argument, file, or stdin) for attacks/leaks")
    s.add_argument("text", nargs="?", help="text to scan; omit to read stdin")
    s.add_argument("--file")
    s.add_argument("--direction", choices=["input", "output"], default="input")

    r = sub.add_parser("redteam", help="evaluate detection on a labelled corpus")
    r.add_argument("--corpus", help="path to custom corpus JSON (default: bundled)")
    r.add_argument("--min-recall", type=float, default=0.0, help="exit 1 if recall below this (CI gate)")

    sub.add_parser("canary", help="generate a canary token and example injection")

    a = p.parse_args(argv)
    if a.cmd == "scan":
        if a.file:
            text = open(a.file, encoding="utf-8").read()
        else:
            text = a.text if a.text is not None else sys.stdin.read()
        res = scan(text, a.direction)
        print(json.dumps(res.to_dict(), indent=2))
        return {"allow": 0, "review": 1, "block": 2}[res.verdict]
    if a.cmd == "redteam":
        m = evaluate(load_corpus(a.corpus))
        print(json.dumps(m, indent=2))
        return 0 if m["recall"] >= a.min_recall else 1
    c = Canary()
    print(c.inject("You are a helpful assistant."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
