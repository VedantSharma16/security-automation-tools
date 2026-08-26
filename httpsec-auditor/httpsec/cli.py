"""Command-line entry point for httpsec-auditor.

Usage: python -m httpsec.cli https://example.com [options]

Only issues passive GET/OPTIONS requests (plus a TLS handshake) against the
target you point it at. Only run this against hosts you own or are
explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

from . import cookies, cors, fetcher, headers, report, tls_inspector
from .models import Finding
from .scoring import SEVERITIES, score_findings

DEFAULT_PROBE_ORIGIN = "https://untrusted-probe.httpsec-auditor.example"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="httpsec-auditor",
        description="Passive HTTP security header, cookie, CORS, and TLS auditor.",
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--port", type=int, default=None, help="TLS port override (default: derived from URL)")
    parser.add_argument("--origin", default=DEFAULT_PROBE_ORIGIN, help="Probe Origin header used for the CORS check")
    parser.add_argument("--no-tls", action="store_true", help="Skip the TLS/certificate check")
    parser.add_argument("--no-cors", action="store_true", help="Skip the CORS probe request")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates (self-signed/staging targets)")
    parser.add_argument("--json-out", metavar="FILE", help="Write the JSON report to FILE")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in console output")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="Only report findings at or above this severity (default: info, i.e. everything)",
    )
    return parser


def run_audit(
    url: str,
    timeout: float = 10.0,
    port: int | None = None,
    probe_origin: str = DEFAULT_PROBE_ORIGIN,
    check_tls: bool = True,
    check_cors: bool = True,
    insecure: bool = False,
) -> tuple[str, list[Finding]]:
    """Orchestrate the fetches + analyzers. Network calls are the only
    non-pure part; everything else delegates to the analyzer modules so
    this function is the single place tests need to mock."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    hostname = parsed.hostname or ""
    tls_port = port or (parsed.port or (443 if scheme == "https" else 80))

    findings: list[Finding] = []

    result = fetcher.fetch(url, timeout=timeout, insecure=insecure)
    findings.extend(headers.analyze_headers(result.headers, scheme=scheme))
    findings.extend(cookies.analyze_cookies(result.set_cookies, scheme=scheme))

    if check_cors:
        cors_result = fetcher.fetch_with_origin(
            result.final_url, origin=probe_origin, timeout=timeout, insecure=insecure
        )
        findings.extend(cors.analyze_cors(cors_result.headers, probe_origin=probe_origin))

    if check_tls and scheme == "https" and hostname:
        tls_info = tls_inspector.inspect(hostname, port=tls_port, timeout=timeout)
        findings.extend(tls_inspector.analyze(tls_info, hostname=hostname))

    return result.final_url, findings


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        target, findings = run_audit(
            args.url,
            timeout=args.timeout,
            port=args.port,
            probe_origin=args.origin,
            check_tls=not args.no_tls,
            check_cors=not args.no_cors,
            insecure=args.insecure,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the user, not swallowed
        print(f"httpsec-auditor: fatal error auditing {args.url}: {exc}", file=sys.stderr)
        return 2

    min_index = SEVERITIES.index(args.min_severity)
    filtered = [f for f in findings if SEVERITIES.index(f.severity) <= min_index]

    score = score_findings(findings)  # score reflects everything found, not just the filtered view
    print(report.render_console(target, filtered, score, use_color=not args.no_color))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(report.render_json(target, findings, score))

    return 1 if filtered else 0


if __name__ == "__main__":
    sys.exit(main())
