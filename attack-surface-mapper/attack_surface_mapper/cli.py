"""Command-line interface for Attack Surface Mapper.

Passive discovery (crt.sh) always runs — it only queries a public
certificate-transparency log aggregator, never the target itself. Active
checks (port scanning, HTTP probing, TLS handshakes) touch the target
directly and require the operator to explicitly confirm authorization
via --i-am-authorized before they run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import httpaudit, portscan, report, scoring, subdomains, tlsaudit
from .models import HostReport, Subdomain

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

AUTHORIZATION_NOTICE = (
    "Active checks (port scan, HTTP probing, TLS handshake) make direct contact "
    "with the target and are skipped unless you pass --i-am-authorized, "
    "confirming you have explicit permission to test this target."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack-surface-mapper",
        description="Authorized external recon: passive subdomain discovery via "
        "certificate transparency, plus active port/header/TLS exposure auditing.",
    )
    parser.add_argument(
        "target", help="Apex domain to enumerate (e.g. example.com), or a single "
        "host with --skip-discovery."
    )
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Treat TARGET as a single host to scan directly, skipping crt.sh enumeration.",
    )
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirm you are authorized to actively probe the resolved target(s), "
        "enabling the port/HTTP/TLS checks.",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Only run passive subdomain discovery; never perform active checks.",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=5,
        help="Maximum number of resolved hosts to actively scan (default: 5).",
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated port list to scan, e.g. '22,80,443' (default: built-in common-port list).",
    )
    parser.add_argument(
        "--timeout", type=float, default=3.0, help="Per-operation network timeout in seconds."
    )
    parser.add_argument(
        "--warn-days",
        type=int,
        default=30,
        help="Flag TLS certificates expiring within this many days (default: 30).",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def _parse_ports(spec: str) -> dict[int, str]:
    ports: dict[int, str] = {}
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        port = int(chunk)
        ports[port] = portscan.COMMON_PORTS.get(port, "unknown")
    return ports


def _discover_targets(args) -> list[Subdomain]:
    if args.skip_discovery:
        ip = subdomains.resolve([args.target], timeout=args.timeout).get(args.target)
        return [Subdomain(name=args.target, ip=ip)]
    return subdomains.discover(args.target, timeout=args.timeout)


def _scan_host(sub: Subdomain, args, port_map: dict[int, str] | None) -> HostReport:
    host, ip = sub.name, sub.ip
    errors: list[str] = []

    if ip is None:
        errors.append("DNS resolution failed — host unreachable, active checks skipped.")
        score, level = scoring.compute_risk([], [])
        return HostReport(
            host=host, ip=None, open_ports=[], findings=[], risk_score=score,
            risk_level=level, errors=errors,
        )

    ports = port_map or portscan.COMMON_PORTS
    open_ports = portscan.scan_host(host, ports=ports, timeout=args.timeout)

    findings = []
    status, headers = httpaudit.fetch_headers(f"https://{host}/", timeout=args.timeout)
    used_scheme = "https"
    if status is None:
        status, headers = httpaudit.fetch_headers(f"http://{host}/", timeout=args.timeout)
        used_scheme = "http"

    if status is not None:
        findings.extend(httpaudit.audit_headers(headers, scheme=used_scheme))
        findings.extend(httpaudit.audit_banner(headers))
    else:
        errors.append("HTTP(S) request failed — host may not be serving web content.")

    if used_scheme == "https" or any(p.port == 443 for p in open_ports):
        cert = tlsaudit.get_certificate(host, timeout=args.timeout)
        findings.extend(tlsaudit.check_expiry(cert, warn_days=args.warn_days))

    score, level = scoring.compute_risk(open_ports, findings)
    return HostReport(
        host=host, ip=ip, open_ports=open_ports, findings=findings,
        risk_score=score, risk_level=level, errors=errors,
    )


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        discovered = _discover_targets(args)
    except Exception as exc:  # noqa: BLE001 - surface any unexpected discovery failure cleanly
        print(f"error: discovery failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not discovered:
        print(f"No subdomains discovered for '{args.target}' (crt.sh empty or unreachable).")
        return EXIT_CLEAN

    print(f"Discovered {len(discovered)} host(s) via passive enumeration:")
    for sub in discovered:
        print(f"  {sub.name}" + (f" -> {sub.ip}" if sub.ip else " (unresolved)"))

    if args.passive_only:
        return EXIT_CLEAN

    if not args.i_am_authorized:
        print(f"\n{AUTHORIZATION_NOTICE}")
        return EXIT_CLEAN

    port_map = _parse_ports(args.ports) if args.ports else None
    resolvable = [s for s in discovered if s.ip is not None]
    active_targets = resolvable[: args.max_hosts]
    if len(resolvable) > args.max_hosts:
        print(
            f"\n{len(resolvable)} host(s) resolved; actively scanning the first "
            f"{args.max_hosts} (raise with --max-hosts)."
        )

    reports = [_scan_host(sub, args, port_map) for sub in active_targets]

    print()
    print(report.render_summary(reports, use_color=not args.no_color))

    if args.json_out:
        report.write_json(reports, args.json_out)

    any_findings = any(r.findings or r.open_ports for r in reports)
    return EXIT_FINDINGS if any_findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
