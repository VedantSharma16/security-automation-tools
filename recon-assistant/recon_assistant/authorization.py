"""Rules-of-engagement guardrail.

Real engagements are scoped in writing before a single packet goes out. This
module encodes that as a hard stop rather than a suggestion: by default, the
tool refuses to scan any target that doesn't resolve to a private/loopback
address unless the operator explicitly passes `--confirm-authorized`. It's a
best-effort guardrail (the check is a resolved-IP range test, not real
authorization enforcement) but it default-denies the common accident of
pointing a scanner at a hostname the operator didn't mean to touch.
"""

from __future__ import annotations

import ipaddress


class AuthorizationError(Exception):
    """Raised when a scan target is refused for lack of confirmed authorization."""


def is_private_or_loopback(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def check_authorization(host: str, ip: str, *, confirmed: bool) -> None:
    """Raise AuthorizationError unless the target is safe-by-default or confirmed."""
    if confirmed:
        return
    if not is_private_or_loopback(ip):
        raise AuthorizationError(
            f"'{host}' resolves to {ip}, which is not a private/loopback address. "
            "Refusing to scan without --confirm-authorized. Only scan systems you "
            "own or have explicit written authorization to test."
        )
