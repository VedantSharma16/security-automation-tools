"""Command-line entry point for Web Security Auditor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import cookies as cookies_mod
from . import cors as cors_mod
from . import disclosure as disclosure_mod
from . import headers as headers_mod
from . import report as report_mod
from . import tls as tls_mod
from .fetcher import fetch, get_tls_info, probe_cors, probe_path

# Exit codes let this tool slot into CI/CD as a gate on a staging deployment.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_CORS_PROBE_ORIGIN = "https://cors-probe.invalid"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-security-auditor",
        description=(
            "Read-only HTTP security audit: security headers, cookie flags, CORS "
            "misconfiguration, TLS/certificate health, and information disclosure. "
            "Only run this against hosts you are authorized to test."
        ),
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10.0,
                         help="Per-request timeout in seconds (default: 10).")
    parser.add_argument(
        "--no-active-probes", action="store_true",
        help="Only analyze the single baseline response (headers/cookies/TLS); skip the "
             "extra sensitive-path and CORS probe requests.",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def run_audit(url: str, timeout: float = 10.0, active_probes: bool = True) -> dict:
    parts = urlsplit(url)
    is_https = parts.scheme == "https"

    baseline = fetch(url, timeout=timeout)
    if baseline.error:
        raise ConnectionError(f"could not reach {url}: {baseline.error}")

    results = []
    results += headers_mod.run_all(baseline.headers, is_https)

    set_cookie_values = [v for k, v in baseline.raw_header_items if k.lower() == "set-cookie"]
    results += cookies_mod.analyze_cookies(set_cookie_values, is_https)

    results += disclosure_mod.analyze_banners(baseline.headers)

    if is_https:
        tls_info = get_tls_info(parts.hostname, parts.port or 443, timeout=timeout)
        results += tls_mod.analyze_tls(tls_info.protocol, tls_info.not_after, tls_info.error)

    if active_probes:
        probe = probe_cors(url, origin=_CORS_PROBE_ORIGIN, timeout=timeout)
        results += cors_mod.analyze_cors(probe.headers, _CORS_PROBE_ORIGIN)

        probe_statuses = {
            path: probe_path(url, path, timeout=timeout).status
            for path in disclosure_mod.SENSITIVE_PATHS
        }
        results += disclosure_mod.analyze_probed_paths(probe_statuses)

    return report_mod.build_report(baseline.final_url, results)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = run_audit(args.url, timeout=args.timeout, active_probes=not args.no_active_probes)
    except ConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)

    return EXIT_FINDINGS if report["summary"].get("fail") else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
