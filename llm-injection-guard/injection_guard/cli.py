"""CLI.

    injection-guard scan "ignore previous instructions" [--source retrieved_doc]
    injection-guard scan --file doc.txt --source web --json
    injection-guard eval [--corpus path.jsonl] [--min-f1 0.9]
"""

from __future__ import annotations

import argparse
import json
import sys

from injection_guard.evaluate import DEFAULT_CORPUS, evaluate, load_corpus
from injection_guard.scanner import SOURCE_MULTIPLIER, scan


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="injection-guard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan text or a file")
    s.add_argument("text", nargs="?")
    s.add_argument("--file")
    s.add_argument("--source", default="user", choices=sorted(SOURCE_MULTIPLIER))
    s.add_argument("--json", action="store_true")
    e = sub.add_parser("eval", help="evaluate detection on a labeled corpus")
    e.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    e.add_argument("--min-f1", type=float, default=0.0, help="exit 1 if F1 is below this (CI gate)")
    a = ap.parse_args(argv)

    if a.cmd == "scan":
        if a.file:
            with open(a.file, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        elif a.text is not None:
            text = a.text
        else:
            ap.error("provide text or --file")
        res = scan(text, a.source)
        if a.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(f"verdict={res.verdict.upper()} score={res.score}/100 source={res.source}")
            for f in res.findings:
                print(f"  [{f.rule_id}] {f.category} (sev {f.severity}, view={f.view}): {f.evidence!r}")
            if res.obfuscation:
                print("  obfuscation:", ", ".join(res.obfuscation))
        return 2 if res.verdict == "block" else 1 if res.verdict == "flag" else 0

    rep = evaluate(load_corpus(a.corpus))
    print(json.dumps(rep.to_dict(), indent=2))
    return 1 if rep.f1 < a.min_f1 else 0


if __name__ == "__main__":
    sys.exit(main())
