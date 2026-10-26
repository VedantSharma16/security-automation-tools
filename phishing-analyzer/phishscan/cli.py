from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .parser import parse_bytes
from .report import to_json, to_markdown
from .scoring import analyze


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phishscan", description="Static phishing email analyzer")
    p.add_argument("eml", type=Path, help="path to a .eml file")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--fail-on", type=int, metavar="SCORE", help="exit 2 if score >= SCORE (for pipelines)")
    args = p.parse_args(argv)
    try:
        raw = args.eml.read_bytes()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    email = parse_bytes(raw)
    verdict = analyze(email)
    print((to_json if args.format == "json" else to_markdown)(email, verdict))
    return 2 if args.fail_on is not None and verdict.score >= args.fail_on else 0


if __name__ == "__main__":
    sys.exit(main())
