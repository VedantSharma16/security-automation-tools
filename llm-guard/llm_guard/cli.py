"""Command line interface."""
from __future__ import annotations

import argparse
import json
import sys

from .redteam import evaluate, load_corpus
from .scanner import Guard


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="llm-guard", description=__doc__)
    p.add_argument("--threshold", type=int, default=40, help="block score threshold (default 40)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan-input", help="scan a prompt (argument or stdin)")
    s.add_argument("text", nargs="?")
    s = sub.add_parser("scan-output", help="scan a model response (argument or stdin)")
    s.add_argument("text", nargs="?")
    s = sub.add_parser("eval", help="run red-team corpus and report detection / false-positive rates")
    s.add_argument("--corpus")
    s.add_argument("--json", action="store_true")
    s.add_argument("--min-detection", type=float, default=0.0, help="exit 1 if below")
    s.add_argument("--max-fpr", type=float, default=1.0, help="exit 1 if above")

    a = p.parse_args(argv)
    guard = Guard(block_threshold=a.threshold)

    if a.cmd == "eval":
        rep = evaluate(guard, load_corpus(a.corpus) if a.corpus else None)
        print(json.dumps(rep.to_dict(), indent=2) if a.json else rep.render())
        ok = rep.detection_rate >= a.min_detection and rep.false_positive_rate <= a.max_fpr
        return 0 if ok else 1

    text = a.text if a.text is not None else sys.stdin.read()
    v = guard.scan_input(text) if a.cmd == "scan-input" else guard.scan_output(text)
    print(json.dumps(v.to_dict(), indent=2))
    return 2 if v.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
