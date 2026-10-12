"""Command line: ``pigard scan``, ``pigard redteam``."""
from __future__ import annotations

import argparse
import json
import sys

from . import harness
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pigard", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan text (file path or '-' for stdin) for prompt injection")
    s.add_argument("input")
    s.add_argument("--source", choices=["user", "retrieved"], default="user")
    s.add_argument("--json", action="store_true")
    r = sub.add_parser("redteam", help="run the attack corpus against a bundled mock target")
    r.add_argument("--target", choices=["vulnerable", "guarded"], default="guarded")
    r.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "scan":
        text = sys.stdin.read() if a.input == "-" else open(a.input, encoding="utf-8").read()
        res = scan(text, a.source)
        if a.json:
            print(json.dumps({"verdict": res.verdict, "risk": res.risk,
                              "findings": [vars(f) for f in res.findings]}, indent=2))
        else:
            print(f"verdict={res.verdict} risk={res.risk}/10")
            for f in res.findings:
                print(f"  [{f.rule_id}] {f.category} ({f.owasp}) sev={f.severity} via {f.view}: {f.evidence!r}")
        return {"allow": 0, "warn": 1, "block": 2}[res.verdict]

    target = harness.guarded_target if a.target == "guarded" else harness.vulnerable_target
    rep = harness.run(target)
    if a.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        for x in rep.results:
            print(f"{x.attack.id} {x.attack.technique:<24} {'LEAKED' if x.leaked else 'held':<7}"
                  f"{'(blocked)' if x.blocked else ''}")
        print(f"leak_rate={rep.leak_rate:.0%} detection_rate={rep.detection_rate:.0%} "
              f"false_positives={rep.false_positives}/{rep.benign_total}")
    return 1 if rep.leak_rate > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
