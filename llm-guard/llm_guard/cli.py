"""Command line interface: scan input/output text and run the red-team eval."""
from __future__ import annotations

import argparse
import json
import sys

from .canary import CanaryToken
from .output_guard import scan_output
from .redteam import DEFAULT_CORPUS, evaluate, load_corpus
from .scanner import scan_input


def _read(args) -> str:
    return args.text if args.text is not None else sys.stdin.read()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="llm-guard", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan prompt text for injection")
    s.add_argument("text", nargs="?", help="text to scan (default: stdin)")
    s.add_argument("--untrusted", action="store_true", help="treat as retrieved/tool content")
    s.add_argument("--json", action="store_true")

    o = sub.add_parser("scan-output", help="scan model output for leaks")
    o.add_argument("text", nargs="?")
    o.add_argument("--canary", help="canary token value to look for")
    o.add_argument("--json", action="store_true")

    r = sub.add_parser("redteam", help="evaluate detector on the labelled corpus")
    r.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    r.add_argument("--block-only", action="store_true", help="count only 'block' as detection")
    r.add_argument("--min-recall", type=float, default=0.0, help="exit 1 if recall is below this")
    r.add_argument("--max-fp", type=int, default=None, help="exit 1 if false positives exceed this")

    sub.add_parser("canary", help="generate a canary token")

    a = p.parse_args(argv)

    if a.cmd == "canary":
        print(CanaryToken().value)
        return 0

    if a.cmd == "redteam":
        rep = evaluate(load_corpus(a.corpus), "block" if a.block_only else "warn")
        print(f"TP={rep.tp} FP={rep.fp} TN={rep.tn} FN={rep.fn}")
        print(f"precision={rep.precision:.2f} recall={rep.recall:.2f} f1={rep.f1:.2f}")
        for m in rep.misses:
            print(f"  MISSED: {m[:80]!r}")
        for m in rep.false_alarms:
            print(f"  FALSE ALARM: {m[:80]!r}")
        bad = rep.recall < a.min_recall or (a.max_fp is not None and rep.fp > a.max_fp)
        return 1 if bad else 0

    if a.cmd == "scan":
        v = scan_input(_read(a), "untrusted" if a.untrusted else "user")
    else:
        v = scan_output(_read(a), CanaryToken(a.canary) if a.canary else None)

    if a.json:
        print(json.dumps(v.to_dict(), indent=2))
    else:
        print(f"{v.action.upper()} (score {v.score}/10)")
        for f in v.findings:
            print(f"  [{f.rule_id}] {f.category} sev={f.severity} {f.owasp} via {f.view}: {f.description}")
    return 2 if v.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
