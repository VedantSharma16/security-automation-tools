"""Command-line entry point for web-security-auditor."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from . import exposure, headers, report, tls_check
from .fetcher import fetch

AUTHORIZATION_NOTICE = """\
web-security-auditor performs live HTTP/TLS requests against the target,
including probes for known-sensitive paths (e.g. .git/HEAD, .env).

Only run this against systems you own or are explicitly authorized to
test. Re-run with --authorized once you have confirmed this.
"""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webauditor",
        description="Passive HTTP security header, TLS, and exposure auditor.",
    )
    parser.add_argument("target", help="Target URL, e.g. https://example.com")
    parser.add_argument(
        "--authorized", action="store_true",
        help="Confirm you are authorized to test the target. Required to run.",
    )
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--skip-tls", action="store_true", help="Skip the TLS certificate check")
    parser.add_argument("--skip-exposure", action="store_true", help="Skip sensitive-path probing")
    parser.add_argument("--json", metavar="PATH", help="Write the full JSON report to PATH")
    parser.add_argument("--quiet", action="store_true", help="Suppress the console report (use with --json)")
    return parser


def run_audit(target: str, timeout: int = 10, skip_tls: bool = False,
              skip_exposure: bool = False, session: requests.Session | None = None) -> dict:
    """Run all enabled checks against target and return a JSON-serializable report."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    all_findings = []

    root = fetch(target, timeout=timeout, session=session)
    if not root.ok:
        all_findings.append(_connection_failed_finding(target, root.error))
    else:
        all_findings.extend(headers.analyze_security_headers(root.headers))
        all_findings.extend(headers.analyze_cookies(root.set_cookie_headers))

        if not skip_tls and parsed.scheme == "https":
            port = parsed.port or 443
            all_findings.extend(tls_check.check_tls(parsed.hostname, port=port, timeout=timeout))

        if not skip_exposure:
            base = f"{parsed.scheme}://{parsed.netloc}"
            all_findings.extend(exposure.check_exposed_paths(
                base, lambda url: fetch(url, timeout=timeout, session=session)
            ))

    generated_at = datetime.now(timezone.utc).isoformat()
    return report.build_report(target, all_findings, generated_at)


def _connection_failed_finding(target: str, error: str | None):
    from .findings import Finding, Severity
    return Finding(
        id="CONN-FAILED",
        title="Could not connect to target",
        severity=Severity.INFO,
        category="connectivity",
        description=f"The initial request to {target} failed: {error}",
        recommendation="Verify the URL is correct and reachable, then retry.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.authorized:
        print(AUTHORIZATION_NOTICE, file=sys.stderr)
        return 2

    audit_report = run_audit(
        args.target,
        timeout=args.timeout,
        skip_tls=args.skip_tls,
        skip_exposure=args.skip_exposure,
    )

    if not args.quiet:
        print(report.render_console(audit_report))

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.render_json(audit_report))

    return 0 if audit_report["summary"]["highest_severity"] not in ("CRITICAL", "HIGH") else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
