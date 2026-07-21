"""Command-line entry point: fetch a URL, run all checks, print/write a report."""

from __future__ import annotations

import argparse
import sys
import urllib.parse

from . import fetcher, grading, report
from .checks import cookies as cookies_check
from .checks import cors as cors_check
from .checks import disclosure as disclosure_check
from .checks import headers as headers_check
from .checks import tls as tls_check
from .models import ScanResult

_GRADE_ORDER = "ABCDF"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscan",
        description=(
            "Passive web application security posture scanner: HTTP security "
            "headers, cookie flags, CORS misconfiguration, and TLS certificate "
            "checks. Only issues standard GET requests and one TLS handshake — "
            "safe against production systems, but only scan targets you are "
            "authorized to assess."
        ),
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com (scheme defaults to https)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10)")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Do not verify TLS certificates when connecting (useful for internal/self-signed targets)",
    )
    parser.add_argument("--no-tls-check", action="store_true", help="Skip the separate TLS handshake/certificate check")
    parser.add_argument(
        "--no-cors-probe",
        action="store_true",
        help="Skip the extra request that tests for CORS Origin reflection",
    )
    parser.add_argument("--json", metavar="PATH", help="Write a JSON report to PATH")
    parser.add_argument("--markdown", metavar="PATH", help="Write a Markdown report to PATH")
    parser.add_argument(
        "--fail-below",
        choices=list(_GRADE_ORDER),
        help="Exit with status 1 if the resulting grade is worse than this threshold (for CI gating)",
    )
    return parser


def normalize_url(url: str) -> str:
    return url if "://" in url else f"https://{url}"


def run_scan(
    url: str,
    timeout: float = 10.0,
    verify_tls: bool = True,
    check_tls: bool = True,
    send_cors_probe: bool = True,
) -> ScanResult:
    target = fetcher.fetch_target(url, timeout=timeout, verify_tls=verify_tls, send_cors_probe=send_cors_probe)

    findings = []
    findings.extend(headers_check.check_security_headers(target))
    findings.extend(cookies_check.check_cookies(target))
    findings.extend(cors_check.check_cors(target))
    findings.extend(disclosure_check.check_info_disclosure(target))

    tls_info = None
    if check_tls and target.final_url.lower().startswith("https://"):
        hostname, port = _host_port(target.final_url)
        if hostname:
            tls_info = fetcher.fetch_tls_info(hostname, port=port, timeout=timeout, verify_tls=verify_tls)
            findings.extend(tls_check.check_tls(tls_info))

    score = grading.compute_score(findings)
    grade = grading.grade_for_score(score)
    return ScanResult(target_url=target.final_url, findings=findings, score=score, grade=grade, tls=tls_info)


def _host_port(url: str) -> tuple[str | None, int]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.hostname, parsed.port or 443


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    url = normalize_url(args.url)

    try:
        result = run_scan(
            url,
            timeout=args.timeout,
            verify_tls=not args.insecure,
            check_tls=not args.no_tls_check,
            send_cors_probe=not args.no_cors_probe,
        )
    except Exception as exc:  # noqa: BLE001 - top-level CLI boundary
        print(f"error: failed to scan {url}: {exc}", file=sys.stderr)
        return 2

    print(report.render_text(result))

    if args.json:
        with open(args.json, "w") as fh:
            fh.write(report.render_json(result))
    if args.markdown:
        with open(args.markdown, "w") as fh:
            fh.write(report.render_markdown(result))

    if args.fail_below and _GRADE_ORDER.index(result.grade) > _GRADE_ORDER.index(args.fail_below):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
