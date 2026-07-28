"""TLS certificate expiry auditing.

Opens a real TLS handshake against the target — another active technique
gated behind the CLI's authorization flag.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from .models import Finding

_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def get_certificate(
    host: str, port: int = 443, timeout: float = 5.0
) -> dict | None:
    """Fetch the leaf certificate's fields for `host:port`, or None on failure."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert()
    except (OSError, ssl.SSLError):
        return None


def check_expiry(
    cert: dict | None, warn_days: int = 30, now: datetime | None = None
) -> list[Finding]:
    """Turn a getpeercert()-shaped dict into expiry Findings.

    - Expired certs are `critical`.
    - Certs expiring within `warn_days` are `high` (or `medium` if the
      total warn window is generous and expiry is still >1 week out).
    """
    if not cert or "notAfter" not in cert:
        return [
            Finding(
                category="tls",
                severity="medium",
                title="Could not verify TLS certificate",
                detail="TLS handshake failed or returned no certificate — host may not be "
                "serving valid HTTPS, or is blocking the probe.",
            )
        ]

    now = now or datetime.now(timezone.utc)
    try:
        expires_at = datetime.strptime(cert["notAfter"], _CERT_DATE_FORMAT).replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return [
            Finding(
                category="tls",
                severity="low",
                title="Unparseable certificate expiry date",
                detail=f"Could not parse notAfter value: {cert['notAfter']!r}",
            )
        ]

    days_left = (expires_at - now).days

    if days_left < 0:
        return [
            Finding(
                category="tls",
                severity="critical",
                title="TLS certificate expired",
                detail=f"Certificate expired {-days_left} day(s) ago ({expires_at.date()}).",
            )
        ]
    if days_left <= 7:
        return [
            Finding(
                category="tls",
                severity="high",
                title="TLS certificate expiring imminently",
                detail=f"Certificate expires in {days_left} day(s) ({expires_at.date()}).",
            )
        ]
    if days_left <= warn_days:
        return [
            Finding(
                category="tls",
                severity="medium",
                title="TLS certificate expiring soon",
                detail=f"Certificate expires in {days_left} day(s) ({expires_at.date()}).",
            )
        ]

    return []
