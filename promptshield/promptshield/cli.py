from __future__ import annotations

import argparse
import json
import sys

from .evaluate import evaluate, load_corpus
from .scanner import Scanner


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="promptshield", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a file (or stdin with -)")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    e = sub.add_parser("eval", help="evaluate on the bundled labeled corpus")
    e.add_argument("--corpus")
    a = p.parse_args(argv)

    if a.cmd == "scan":
        text = sys.stdin.read() if a.path == "-" else open(a.path, encoding="utf-8").read()
        res = Scanner().scan(text)
        if a.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(f"verdict={res.verdict} score={res.score}")
            for f in res.findings:
                print(f"  [{f.rule_id}] {f.category} sev={f.severity} {f.owasp}: {f.excerpt!r}")
        return {"clean": 0, "suspicious": 1, "block": 2}[res.verdict]

    kw = {"path": a.corpus} if a.corpus else {}
    r = evaluate(load_corpus(**kw))
    print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
