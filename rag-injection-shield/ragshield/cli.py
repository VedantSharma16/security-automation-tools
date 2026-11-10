"""CLI: ragshield scan <paths...> [--json] [--fail-on quarantine|block]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_text

TEXT_EXT = {".txt", ".md", ".html", ".htm", ".json", ".csv", ".log", ".rst"}
LEVEL = {"allow": 0, "quarantine": 1, "block": 2}


def _iter_files(paths):
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in TEXT_EXT)
        else:
            yield p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ragshield", description="Scan documents for indirect prompt injection.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan files/directories (use - for stdin)")
    sc.add_argument("paths", nargs="+")
    sc.add_argument("--json", action="store_true", help="machine-readable output")
    sc.add_argument("--fail-on", choices=["quarantine", "block"], default="block",
                    help="exit 1 if any document reaches this verdict (default: block)")
    args = ap.parse_args(argv)

    reports, worst = [], 0
    targets = [("<stdin>", sys.stdin.read())] if args.paths == ["-"] else [
        (str(f), f.read_text(encoding="utf-8", errors="replace")) for f in _iter_files(args.paths)]
    for name, text in targets:
        res = scan_text(text)
        worst = max(worst, LEVEL[res.verdict])
        reports.append((name, res))

    if args.json:
        print(json.dumps([{"file": n, **r.to_dict()} for n, r in reports], indent=2))
    else:
        for name, r in reports:
            print(f"[{r.verdict.upper():<10}] score={r.score:>3}  {name}")
            for e in r.evasions:
                print(f"    evasion: {e}")
            for f in r.findings:
                print(f"    {f.rule_id} {f.category} (sev {f.severity}, {f.source}): ...{f.excerpt}...")
    return 1 if worst >= LEVEL[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
