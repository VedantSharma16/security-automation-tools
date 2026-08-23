"""TLS certificate and protocol posture checks.

Connects with a standard verifying SSL context (the same trust store a
browser would use) to pull certificate metadata and the negotiated
protocol/cipher, then flags expiry and outdated-protocol risk. A separate,
non-verifying probe is used only to distinguish "certificate is invalid"
from "host unreachable" so the finding text is accurate either way.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl

from .findings import Finding

_CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TLSCheckError(Exception):
    pass


def _default_probe(host: str, port: int, timeout: float, verify: bool):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert() if verify else None
            protocol = tls_sock.version()
            cipher = tls_sock.cipher()
    return cert, protocol, cipher


def get_certificate_info(
    host: str, port: int = 443, timeout: float = 5.0, probe=_default_probe
) -> dict:
    """Return cert/protocol/cipher info, or a dict flagging why verification failed."""
    try:
        cert, protocol, cipher = probe(host, port, timeout, True)
    except ssl.SSLCertVerificationError as exc:
        # Certificate chain didn't validate (self-signed, expired CA, hostname
        # mismatch, ...). Reconnect without verification just to still report
        # protocol/expiry information alongside the trust failure.
        try:
            cert, protocol, cipher = probe(host, port, timeout, False)
        except OSError as inner_exc:
            raise TLSCheckError(f"could not connect to {host}:{port}: {inner_exc}") from inner_exc
        return {
            "host": host,
            "port": port,
            "trusted": False,
            "verification_error": str(exc),
            "cert": cert,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
        }
    except (socket.timeout, OSError) as exc:
        raise TLSCheckError(f"could not connect to {host}:{port}: {exc}") from exc

    return {
        "host": host,
        "port": port,
        "trusted": True,
        "verification_error": None,
        "cert": cert,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
    }


def _parse_not_after(cert: dict) -> dt.datetime | None:
    not_after = cert.get("notAfter") if cert else None
    if not not_after:
        return None
    return dt.datetime.strptime(not_after, _CERT_DATE_FMT).replace(tzinfo=dt.timezone.utc)


def analyze_certificate(info: dict, now: dt.datetime | None = None) -> list[Finding]:
    now = now or dt.datetime.now(dt.timezone.utc)
    findings: list[Finding] = []
    host, port = info["host"], info["port"]

    if not info["trusted"]:
        findings.append(
            Finding(
                category="tls",
                title="TLS certificate failed validation",
                severity="high",
                description=(
                    f"The certificate presented by {host}:{port} did not validate "
                    f"against the system trust store: {info['verification_error']}"
                ),
                recommendation=(
                    "Install a certificate from a trusted CA (or fix the chain/hostname "
                    "mismatch) — browsers will show a hard warning to visitors otherwise."
                ),
                evidence={"host": host, "port": port},
            )
        )

    if info["protocol"] and info["protocol"] in _WEAK_PROTOCOLS:
        findings.append(
            Finding(
                category="tls",
                title=f"Outdated TLS protocol negotiated: {info['protocol']}",
                severity="high",
                description=(
                    f"{host}:{port} negotiated {info['protocol']}, which has known "
                    "cryptographic weaknesses and is deprecated by all major browsers."
                ),
                recommendation="Disable protocols below TLS 1.2 on the server.",
                evidence={"protocol": info["protocol"]},
            )
        )

    not_after = _parse_not_after(info.get("cert"))
    if not_after:
        days_left = (not_after - now).days
        if days_left < 0:
            findings.append(
                Finding(
                    category="tls",
                    title="TLS certificate has expired",
                    severity="critical",
                    description=f"The certificate for {host} expired on {not_after.date()}.",
                    recommendation="Renew the certificate immediately.",
                    evidence={"not_after": info["cert"]["notAfter"]},
                )
            )
        elif days_left <= 14:
            findings.append(
                Finding(
                    category="tls",
                    title="TLS certificate expiring soon",
                    severity="high",
                    description=f"The certificate for {host} expires in {days_left} day(s) ({not_after.date()}).",
                    recommendation="Renew the certificate before it expires to avoid an outage.",
                    evidence={"not_after": info["cert"]["notAfter"], "days_left": days_left},
                )
            )
        elif days_left <= 30:
            findings.append(
                Finding(
                    category="tls",
                    title="TLS certificate expiring within 30 days",
                    severity="medium",
                    description=f"The certificate for {host} expires in {days_left} day(s) ({not_after.date()}).",
                    recommendation="Schedule renewal ahead of expiry.",
                    evidence={"not_after": info["cert"]["notAfter"], "days_left": days_left},
                )
            )

    return findings
