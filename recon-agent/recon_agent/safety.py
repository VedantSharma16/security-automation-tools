"""Target-authorization guardrails.

Scanning or fingerprinting a system you don't own and don't have explicit
permission to test is illegal in most jurisdictions, full stop. This module
enforces one simple default: private/loopback targets are always allowed
(you're almost certainly testing your own lab or a local test container),
anything else requires an explicit `--authorized` confirmation on the CLI.
This check runs before a single packet is sent.
"""

from __future__ import annotations

import ipaddress
import socket


class UnauthorizedTargetError(RuntimeError):
    """Raised when a non-private target is scanned without --authorized."""


def is_private_target(target: str) -> bool:
    """True if `target` is a loopback/private-range IP, or a hostname that
    resolves to one. Unresolvable hostnames are treated as NOT private, so
    they fall back to requiring explicit authorization."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            resolved = socket.gethostbyname(target)
            ip = ipaddress.ip_address(resolved)
        except (socket.gaierror, ValueError, OSError):
            return False
    return ip.is_private or ip.is_loopback


def check_authorization(target: str, authorized_flag: bool) -> None:
    """Raise UnauthorizedTargetError unless the target is private/loopback
    or the caller has explicitly confirmed authorization."""
    if is_private_target(target):
        return
    if not authorized_flag:
        raise UnauthorizedTargetError(
            f"'{target}' does not resolve to a private/loopback address. "
            "Re-run with --authorized to confirm you have explicit written "
            "permission to test this target. Scanning systems without "
            "authorization may be illegal."
        )
