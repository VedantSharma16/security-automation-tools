"""Command-line interface for Web Recon Scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

import requests

from . import fingerprint as fingerprint_mod
from . import headers as headers_mod
from . import report as report_mod
from . import robots as robots_mod
from . import subdomains as subdomains_mod
from . import tls_check

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DISCLAIMER = (
    "Web Recon Scanner sends live HTTP/TLS/DNS requests to the target. "
    "Only run it against systems you own or are explicitly authorized to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-recon-scanner",
        description="Web reconnaissance: security headers, TLS/certificate checks, "
        "technology fingerprinting, robots.txt/sitemap review, and optional subdomain enumeration.",
    )
    parser.add_argument("target", help="Target URL or hostname, e.g. https://example.com")
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Required acknowledgment that you own or are authorized to test the target.",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10).")
    parser.add_argument(
        "--enumerate-subdomains",
        action="store_true",
        help="Also brute-force common subdomains via DNS (slower, more active than the default checks).",
    )
    parser.add_argument("--subdomain-wordlist", type=Path, help="Custom subdomain wordlist (one entry per line).")
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def _base_url_and_host(target: str):
    if "://" not in target:
        target = f"https://{target}"
    parts = urlsplit(target)
    return f"{parts.scheme}://{parts.netloc}", parts.hostname


def _fetch_cookie_headers(resp) -> list:
    raw_headers = getattr(resp.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "get_all"):
        return raw_headers.get_all("Set-Cookie") or []
    return []


def run(args, session=None) -> report_mod.ScanReport:
    http = session or requests
    base_url, host = _base_url_and_host(args.target)

    header_findings = []
    technologies = []
    robots_findings = None
    sitemap_urls = []
    tls_report = None
    subdomains = []
    errors = []

    try:
        resp = http.get(base_url, timeout=args.timeout, allow_redirects=True)
        header_findings = headers_mod.analyze_headers(dict(resp.headers))
        header_findings += headers_mod.analyze_cookies(_fetch_cookie_headers(resp))
        signatures = fingerprint_mod.load_signatures()
        technologies = fingerprint_mod.fingerprint(dict(resp.headers), resp.text, signatures)
    except requests.RequestException as exc:
        errors.append(f"HTTP fetch of {base_url} failed: {exc}")

    try:
        robots_resp = http.get(f"{base_url}/robots.txt", timeout=args.timeout)
        if robots_resp.status_code == 200:
            robots_findings = robots_mod.parse_robots_txt(robots_resp.text)
            for sitemap_url in robots_findings.sitemaps:
                try:
                    sitemap_resp = http.get(sitemap_url, timeout=args.timeout)
                    if sitemap_resp.status_code == 200:
                        sitemap_urls.extend(robots_mod.parse_sitemap_xml(sitemap_resp.text))
                except requests.RequestException as exc:
                    errors.append(f"Sitemap fetch failed for {sitemap_url}: {exc}")
    except requests.RequestException as exc:
        errors.append(f"robots.txt fetch failed: {exc}")

    try:
        cert, protocol_version = tls_check.fetch_certificate(host, timeout=args.timeout)
        tls_report = tls_check.inspect_certificate(cert, protocol_version)
    except Exception as exc:  # noqa: BLE001 - any handshake/socket failure shouldn't abort the scan
        errors.append(f"TLS check failed: {exc}")

    if args.enumerate_subdomains:
        wordlist = subdomains_mod.load_wordlist(args.subdomain_wordlist) if args.subdomain_wordlist else subdomains_mod.load_wordlist()
        subdomains = subdomains_mod.enumerate_subdomains(host, wordlist)

    return report_mod.build_report(
        target=base_url,
        header_findings=header_findings,
        tls_report=tls_report,
        technologies=technologies,
        robots_findings=robots_findings,
        sitemap_urls=sitemap_urls,
        subdomains=subdomains,
        errors=errors,
    )


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(DISCLAIMER, file=sys.stderr)
    if not args.i_own_this_target:
        print(
            "Refusing to scan: pass --i-own-this-target to confirm you own or are "
            "authorized to test this target.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    report = run(args)
    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)

    if report.errors and not (report.header_findings or report.tls_report or report.technologies):
        return EXIT_ERROR

    return EXIT_FINDINGS if report_mod.risk_score(report) > 0 else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
