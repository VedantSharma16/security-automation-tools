"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detectors import detect_all
from .parser import parse_message
from .report import render_json, render_text
from .scoring import score


def analyze(raw: bytes):
    p = parse_message(raw)
    findings = detect_all(p)
    risk, verdict = score(findings)
    return p, findings, risk, verdict


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishtriage", description="Analyze a suspected phishing email (.eml).")
    ap.add_argument("eml", type=Path, help="path to .eml file")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)
    try:
        raw = args.eml.read_bytes()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    result = analyze(raw)
    print(render_json(*result) if args.json else render_text(*result))
    # exit code lets this gate a mail pipeline: 0 clean/low, 1 suspicious, 2+ malicious handled as 3
    return {"clean": 0, "low-risk": 0, "suspicious": 1, "malicious": 3}[result[3]]


if __name__ == "__main__":
    sys.exit(main())
