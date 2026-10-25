"""Command line: ``prompt-shield scan`` and ``prompt-shield eval``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detector import scan
from .evaluate import evaluate, load_corpus

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "data" / "corpus.jsonl"
EXIT_CODES = {"allow": 0, "suspicious": 1, "block": 2}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prompt-shield", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan text (argument, file, or stdin) for prompt injection")
    s.add_argument("text", nargs="?", help="text to scan; use --file or pipe stdin otherwise")
    s.add_argument("--file", help="read text from a file")
    s.add_argument("--json", action="store_true", help="emit JSON")
    e = sub.add_parser("eval", help="measure precision/recall on a labelled JSONL corpus")
    e.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    e.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        if args.file:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        elif args.text is not None:
            text = args.text
        else:
            text = sys.stdin.read()
        v = scan(text)
        if args.json:
            print(json.dumps(v.to_dict(), indent=2))
        else:
            print(f"{v.label.upper()}  score={v.score:.2f}")
            for f in v.findings:
                print(f"  [{f.rule_id}] sev={f.severity} {f.category} ({f.source}): {f.evidence!r}")
        return EXIT_CODES[v.label]
    m = evaluate(load_corpus(args.corpus))
    if args.json:
        print(json.dumps(m.to_dict(), indent=2))
    else:
        print(f"precision={m.precision:.3f} recall={m.recall:.3f} f1={m.f1:.3f} accuracy={m.accuracy:.3f}")
        print(f"TP={m.tp} FP={m.fp} TN={m.tn} FN={m.fn}")
        for cat, r in m.recall_by_category.items():
            print(f"  recall[{cat}] = {r:.2f}")
        for t in m.missed:
            print(f"  MISSED: {t}")
        for t in m.false_alarms:
            print(f"  FALSE ALARM: {t}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
