"""Authorization guard rail.

Recon tooling is dual-use by nature. This module refuses to run against a
target that doesn't resolve to a private/loopback address unless the
operator explicitly confirms authorization on the command line — a small
speed bump against accidentally (or casually) pointing the tool at
infrastructure nobody agreed to have tested.
"""

from __future__ import annotations

import ipaddress
import socket

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


class AuthorizationError(Exception):
    """Raised when a target requires, but lacks, an authorization confirmation."""


def is_private_target(host: str) -> bool:
    """Return True if ``host`` resolves to a loopback or RFC1918 address.

    Unresolvable hosts are treated as *not* private (fails safe: an
    unresolvable name still requires explicit authorization to scan).
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, OSError):
            return False
    return ip.is_loopback or any(ip in net for net in PRIVATE_NETWORKS)


def check_authorization(target: str, confirmed: bool) -> None:
    """Raise :class:`AuthorizationError` for a non-private target without confirmation."""
    if is_private_target(target):
        return
    if not confirmed:
        raise AuthorizationError(
            f"'{target}' does not resolve to a private/loopback address. "
            "Only run recon-agent against systems you are explicitly authorized "
            "to test (your own lab, a CTF box, or a signed pentest engagement). "
            "Re-run with --i-have-authorization once you've confirmed that."
        )
