from __future__ import annotations

import argparse
import sys

from .parser import parse_file
from .report import to_json, to_text
from .scoring import assess


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishtriage", description="Triage a suspicious .eml file offline.")
    ap.add_argument("eml", help="path to .eml file")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--fail-on", choices=["SUSPICIOUS", "MALICIOUS"], help="exit 2 at/above this verdict (for pipelines)")
    args = ap.parse_args(argv)
    try:
        p = parse_file(args.eml)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    v = assess(p)
    print(to_json(p, v) if args.json else to_text(p, v))
    if args.fail_on:
        rank = ["CLEAN", "LOW-RISK", "SUSPICIOUS", "MALICIOUS"]
        if rank.index(v.label) >= rank.index(args.fail_on):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
