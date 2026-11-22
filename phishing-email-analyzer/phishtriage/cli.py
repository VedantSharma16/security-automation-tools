"""Command-line entry point: `phishtriage analyze <file-or-dir> [...]`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzers import run_all
from .narrative import DEFAULT_MODEL, get_narrator, safe_narrate
from .parser import parse_file
from .report import build_report, render_markdown
from .scoring import assess

EXIT_CODES = {"benign": 0, "suspicious": 1, "likely-phishing": 2, "malicious": 3}


def analyze_path(path: Path) -> dict:
    email = parse_file(path)
    return build_report(email, assess(run_all(email)), source=str(path))


def _collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(p.glob("*.eml")))
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(p)
    return files


def _batch_table(reports: list[dict]) -> str:
    rows = ["| Verdict | Score | File | Subject |", "|---|---|---|---|"]
    for r in sorted(reports, key=lambda r: r["score"], reverse=True):
        subject = r["message"]["subject"].replace("|", "\\|")
        rows.append(f"| {r['verdict']} | {r['score']} | {Path(r['source']).name} | {subject} |")
    return "# Phishing Triage — Batch Summary\n\n" + "\n".join(rows) + "\n"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="phishtriage", description="Explainable phishing email triage.")
    sub = ap.add_subparsers(dest="command", required=True)
    an = sub.add_parser("analyze", help="Analyze one or more .eml files or directories of them.")
    an.add_argument("paths", nargs="+")
    an.add_argument("--format", choices=["markdown", "json"], default="markdown")
    an.add_argument("--out", help="Write output to this file instead of stdout.")
    an.add_argument("--llm", action="store_true", help="Use Claude for the analyst narrative.")
    an.add_argument("--model", default=DEFAULT_MODEL)
    an.add_argument("--no-narrative", action="store_true", help="Skip the narrative section.")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        files = _collect(args.paths)
    except FileNotFoundError as exc:
        print(f"error: no such file or directory: {exc}", file=sys.stderr)
        return 64
    if not files:
        print("error: no .eml files found", file=sys.stderr)
        return 64

    narrator = None if args.no_narrative else get_narrator(args.llm, args.model)
    reports = []
    for f in files:
        report = analyze_path(f)
        if narrator:
            report["narrative"] = safe_narrate(narrator, report)
        reports.append(report)

    if args.format == "json":
        output = json.dumps(reports[0] if len(reports) == 1 else reports, indent=2)
    else:
        sections = [render_markdown(r, r.get("narrative", "")) for r in reports]
        if len(reports) > 1:
            sections.insert(0, _batch_table(reports))
        output = "\n---\n\n".join(sections)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(output)

    # Exit code reflects the worst verdict, so the tool can gate automation (SOAR, CI).
    return max(EXIT_CODES[r["verdict"]] for r in reports)


if __name__ == "__main__":
    sys.exit(main())
