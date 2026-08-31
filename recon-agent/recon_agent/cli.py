"""Command-line entry point for the recon agent."""

from __future__ import annotations

import argparse
import sys

from .agent import ReconAgent
from .report import to_json, to_markdown

BANNER = (
    "recon-agent performs passive reconnaissance only (DNS, an HTTP GET, "
    "robots.txt, a TLS handshake) — no port scanning, exploitation, or "
    "brute forcing. Only run it against domains you own or are explicitly "
    "authorized to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description="Agentic passive-recon assistant for authorized security testing.",
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirm you own this domain or have explicit written authorization to test it.",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of Markdown.")
    parser.add_argument(
        "--scheme", default="https", choices=["https", "http"], help="Scheme for the HTTP check."
    )
    parser.add_argument(
        "--max-iterations", type=int, default=6, help="Max tool-call rounds in live LLM mode."
    )
    return parser


def main(argv: "list[str] | None" = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.i_have_authorization:
        print(BANNER, file=sys.stderr)
        print(
            "\nRefusing to run: pass --i-have-authorization to confirm you are "
            "authorized to test this target.",
            file=sys.stderr,
        )
        return 2

    from .tools import ToolRegistry

    registry = ToolRegistry(args.domain, scheme=args.scheme)
    agent = ReconAgent(args.domain, registry=registry, max_iterations=args.max_iterations)
    report = agent.run()

    print(to_json(report) if args.json else to_markdown(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
