import argparse
import json
import sys

from .detector import scan
from .redteam import format_report, load_payloads, run_campaign
from .targets import naive_llm, shielded


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="injectionshield", description="Prompt-injection scanner and red-team harness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan text (argument, file, or stdin) for prompt injection")
    s.add_argument("text", nargs="?", help="text to scan; omit to read stdin")
    s.add_argument("--json", action="store_true")
    r = sub.add_parser("redteam", help="run the payload corpus against unguarded vs shielded simulated apps")
    r.add_argument("--payloads", help="custom payload JSON file")
    r.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "scan":
        res = scan(args.text if args.text is not None else sys.stdin.read())
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(f"verdict={res.verdict} score={res.score} obfuscation={res.obfuscation or 'none'}")
            for f in res.findings:
                print(f"  [{f.rule_id}] {f.category} (w{f.weight}, {f.via}): {f.excerpt!r}")
        return {"allow": 0, "warn": 1, "block": 2}[res.verdict]

    payloads = load_payloads(args.payloads)
    results = {"unguarded": run_campaign(naive_llm, payloads),
               "shielded": run_campaign(shielded(naive_llm), payloads)}
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for name, res in results.items():
            print(format_report(name, res), end="\n\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
