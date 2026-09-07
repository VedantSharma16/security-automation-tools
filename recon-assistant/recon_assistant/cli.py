"""Command-line interface for recon-assistant."""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

from . import http_audit
from . import llm_summarizer
from . import report as report_mod
from .authorization import AuthorizationError, check_authorization
from .fingerprint import fingerprint_port
from .ports import DEFAULT_PORTS, parse_ports
from .scanner import scan_ports

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-assistant",
        description="Authorized-engagement network recon: async port scanning, "
        "passive service fingerprinting, HTTP security-header auditing, and an "
        "optional LLM-written findings narrative.",
    )
    parser.add_argument("target", help="Hostname or IP address to scan.")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Comma-separated ports and/or ranges, e.g. '22,80,8000-8010'.",
    )
    parser.add_argument("--concurrency", type=int, default=200)
    parser.add_argument(
        "--timeout", type=float, default=1.0, help="Per-port connect timeout, in seconds."
    )
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm you have explicit written authorization to scan this "
        "target. Required for any target that does not resolve to a "
        "private/loopback address.",
    )
    parser.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="info",
        help="Only report findings at or above this severity (default: info).",
    )
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--out", type=Path, help="Write the report to this path instead of stdout.")
    parser.add_argument(
        "--llm", action="store_true", help="Use Claude for the narrative section (requires ANTHROPIC_API_KEY)."
    )
    parser.add_argument("--model", default="claude-sonnet-5")
    return parser


def run(args: argparse.Namespace, *, resolve_fn=None) -> dict:
    ip = (resolve_fn or socket.gethostbyname)(args.target)
    check_authorization(args.target, ip, confirmed=args.confirm_authorized)

    ports = parse_ports(args.ports)
    port_results = scan_ports(ip, ports, concurrency=args.concurrency, timeout=args.timeout)
    open_ports = [r for r in port_results if r.open]

    findings = []
    for r in open_ports:
        findings.extend(fingerprint_port(r.port, r.banner))
    findings.extend(http_audit.audit_open_ports(ip, [r.port for r in open_ports]))

    report = report_mod.build_report(args.target, ip, port_results, findings)
    return report_mod.filter_by_min_severity(report, args.min_severity)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = run(args)
    except AuthorizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except socket.gaierror as exc:
        print(f"error: could not resolve '{args.target}': {exc}", file=sys.stderr)
        return EXIT_ERROR

    summarizer = llm_summarizer.get_summarizer(args.llm, model=args.model)
    narrative = summarizer.summarize(report)

    if args.format == "json":
        payload = dict(report)
        payload["narrative"] = narrative
        output = report_mod.render_json(payload)
    else:
        output = report_mod.render_markdown(report, narrative=narrative)

    if args.out:
        args.out.write_text(output)
    else:
        print(output)

    return EXIT_FINDINGS if report["findings"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
