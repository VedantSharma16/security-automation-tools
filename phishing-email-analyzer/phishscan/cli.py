from __future__ import annotations

import argparse
import sys

from .analyzer import analyze, load_message
from .report import to_json, to_text

EXIT_CODES = {"clean": 0, "suspicious": 1, "likely_phishing": 2}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishscan", description="Offline phishing email triage for .eml files.")
    ap.add_argument("eml", nargs="+", help="path(s) to .eml file(s)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)

    worst = 0
    for path in args.eml:
        try:
            result = analyze(load_message(path))
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
        print(to_json(result) if args.json else to_text(result))
        worst = max(worst, EXIT_CODES[result["label"]])
    return worst  # usable as a mail-gateway / SOAR gate


if __name__ == "__main__":
    sys.exit(main())
