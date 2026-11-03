"""CLI: ``llm-guard scan``, ``llm-guard redteam``."""
from __future__ import annotations

import argparse
import json
import sys

from .redteam import run_redteam, vulnerable_demo_target
from .scanner import Scanner


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="llm-guard", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan text from a file or stdin ('-')")
    s.add_argument("path", nargs="?", default="-")
    s.add_argument("--mode", choices=["input", "output"], default="input")
    s.add_argument("--json", action="store_true")
    sub.add_parser("redteam", help="run the attack corpus against the demo vulnerable bot")
    a = p.parse_args(argv)

    if a.cmd == "scan":
        text = sys.stdin.read() if a.path == "-" else open(a.path, encoding="utf-8").read()
        r = Scanner().scan(text, a.mode)
        if a.json:
            print(json.dumps(r.to_dict(), indent=2))
        else:
            print(f"verdict={r.verdict} score={r.score}/10 obfuscation={r.obfuscation or '-'}")
            for f in r.findings:
                print(f"  [{f.severity}] {f.rule_id} {f.name} ({f.category}, {f.atlas}) via {f.view}: {f.evidence}")
        return {"allow": 0, "review": 1, "block": 2}[r.verdict]

    for label, guard in (("UNGUARDED", None), ("GUARDED", Scanner())):
        rep = run_redteam(vulnerable_demo_target, guard)
        print(f"== {label}: attack success {rep.attack_success_rate:.0%}, false positives {rep.false_positives}")
        for o in rep.outcomes:
            state = f"blocked@{o.blocked_at}" if o.blocked_at else ("COMPROMISED" if o.succeeded else "ok")
            print(f"  {o.attack.id} {o.attack.technique:<26} {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
