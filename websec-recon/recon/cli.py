"""Command-line interface for websec-recon.

IMPORTANT: only run this against hosts you own or are explicitly authorized
to test. Port scanning and subdomain enumeration against systems you don't
have permission to assess may violate the law (e.g. the U.S. CFAA) and the
target's terms of service, even when the checks themselves are passive/low
volume.
"""

from __future__ import annotations

import argparse
import sys

from . import dns_enum, http_headers, port_scan, report as report_mod, tls_check
from .findings import SEVERITIES, Finding

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec-recon",
        description=(
            "Authorized external recon: subdomain enumeration, TCP port scan, "
            "HTTP security header analysis, and TLS certificate checks, merged "
            "into one scored report."
        ),
    )
    parser.add_argument("target", help="Domain to scan, e.g. example.com")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="Only report findings at or above this severity (default: info).",
    )
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration.")
    parser.add_argument("--no-ports", action="store_true", help="Skip the port scan.")
    parser.add_argument("--no-headers", action="store_true", help="Skip HTTP header analysis.")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS certificate checks.")
    parser.add_argument(
        "--port-timeout", type=float, default=1.0, help="Per-port connect timeout in seconds."
    )
    parser.add_argument("--json-out", help="Write the full JSON report to this path.")
    parser.add_argument("--md-out", help="Write a Markdown report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def _resolve_target_ip(target: str) -> str | None:
    return dns_enum._default_resolver(target)  # noqa: SLF001 (internal reuse within the package)


def run_scan(args) -> list[Finding]:
    findings: list[Finding] = []

    if not args.no_subdomains:
        resolved = dns_enum.enumerate_subdomains(args.target)
        findings += dns_enum.analyze_subdomains(args.target, resolved)

    if not args.no_ports:
        ip = _resolve_target_ip(args.target)
        if ip is None:
            print(f"warning: could not resolve {args.target}, skipping port scan", file=sys.stderr)
        else:
            open_ports = port_scan.scan_ports(ip, timeout=args.port_timeout)
            findings += port_scan.analyze_ports(args.target, open_ports)

    if not args.no_headers:
        try:
            result = http_headers.fetch_headers(f"https://{args.target}/")
            findings += http_headers.analyze_headers(result)
        except http_headers.FetchError as exc:
            print(f"warning: {exc}", file=sys.stderr)

    if not args.no_tls:
        try:
            info = tls_check.get_certificate_info(args.target)
            findings += tls_check.analyze_certificate(info)
        except tls_check.TLSCheckError as exc:
            print(f"warning: {exc}", file=sys.stderr)

    return findings


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        findings = run_scan(args)
    except KeyboardInterrupt:
        return EXIT_CLEAN

    report = report_mod.build_report(args.target, findings)
    report = report_mod.filter_by_min_severity(report, args.min_severity)

    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)
    if args.md_out:
        report_mod.write_markdown(report, args.md_out)

    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
