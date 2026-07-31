"""Command-line entry point for web-security-auditor."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .auditor import audit_url
from .fetcher import DEFAULT_TIMEOUT
from .report import render_json, render_text
from .scoring import GRADE_THRESHOLDS

_GRADE_RANK = {grade: threshold for threshold, grade in GRADE_THRESHOLDS}
_GRADE_RANK["F"] = 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webauditor",
        description=(
            "Passively audit one or more URLs for missing/weak HTTP security headers, "
            "cookie hardening, and TLS certificate posture. Only sends normal GET requests -- "
            "safe to run against any host you are authorized to test."
        ),
    )
    parser.add_argument("urls", nargs="+", help="One or more URLs to audit (e.g. https://example.com)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--no-tls", action="store_true", help="Skip the TLS certificate/handshake check")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text")
    parser.add_argument(
        "--min-grade",
        choices=sorted(_GRADE_RANK, key=lambda g: _GRADE_RANK[g]),
        default=None,
        help="Exit with a non-zero status if any audited URL scores below this letter grade (useful in CI)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    results = [audit_url(url, timeout=args.timeout, skip_tls=args.no_tls) for url in args.urls]

    if args.json:
        print(json.dumps([json.loads(render_json(r)) for r in results], indent=2))
    else:
        for i, result in enumerate(results):
            if i:
                print("\n" + "-" * 60 + "\n")
            print(render_text(result))

    if args.min_grade is not None:
        threshold = _GRADE_RANK[args.min_grade]
        if any(_GRADE_RANK.get(r.grade, 0) < threshold for r in results):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
