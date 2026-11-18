"""Header forensics: SPF/DKIM/DMARC verdicts and the Received hop chain.

Authentication-Results (RFC 8601) is only trustworthy when stamped by *your*
receiving MTA, so callers may pass ``trusted_authserv_ids`` to ignore results
an attacker forged into the message before it reached you. With no trusted
IDs configured, the top-most (most recently added) header is used, which is
the one your own gateway normally prepends.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime

from .parser import ParsedEmail

_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)", re.IGNORECASE)
_HEADER_D_RE = re.compile(r"header\.(?:d|i|from)\s*=\s*@?([\w.-]+)", re.IGNORECASE)
_SMTP_MAILFROM_RE = re.compile(r"smtp\.mailfrom\s*=\s*(?:[^@\s;]*@)?([\w.-]+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
_FROM_HOST_RE = re.compile(r"^\s*from\s+(\S+)", re.IGNORECASE)
_BY_HOST_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)


@dataclass
class AuthResults:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    authserv_id: str = ""
    dkim_domains: list[str] = field(default_factory=list)
    spf_domain: str = ""
    source: str = "absent"  # "authentication-results", "received-spf", or "absent"

    def to_dict(self) -> dict:
        return {
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "authserv_id": self.authserv_id,
            "dkim_domains": self.dkim_domains,
            "spf_domain": self.spf_domain,
            "source": self.source,
        }


@dataclass
class Hop:
    index: int
    from_host: str
    by_host: str
    ip: str
    timestamp: datetime | None
    delay_seconds: float | None = None

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "from_host": self.from_host,
            "by_host": self.by_host,
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "delay_seconds": self.delay_seconds,
        }


def _is_private(ip: str) -> bool:
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return True
    return (
        a in (10, 127, 0)
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 169 and b == 254)
        or a >= 224
    )


def parse_auth_results(email: ParsedEmail, trusted_authserv_ids: list[str] | None = None) -> AuthResults:
    candidates = email.header_values("Authentication-Results")
    if trusted_authserv_ids:
        trusted = {t.lower() for t in trusted_authserv_ids}
        candidates = [c for c in candidates if c.split(";", 1)[0].strip().lower() in trusted]

    if candidates:
        raw = " ".join(candidates[0].split())  # unfold
        res = AuthResults(authserv_id=raw.split(";", 1)[0].strip(), source="authentication-results")
        for method, result in _METHOD_RE.findall(raw):
            method, result = method.lower(), result.lower()
            # Keep the first verdict for each method, except let a dkim=pass win
            # over other signatures (a message can carry several).
            if method == "dkim" and res.dkim != "none":
                if result == "pass":
                    res.dkim = "pass"
                continue
            if method in ("spf", "dkim", "dmarc"):
                setattr(res, method, result)
        res.dkim_domains = sorted({d.lower() for d in _HEADER_D_RE.findall(raw)})
        m = _SMTP_MAILFROM_RE.search(raw)
        res.spf_domain = m.group(1).lower() if m else ""
        return res

    received_spf = email.header_values("Received-SPF")
    if received_spf:
        verdict = received_spf[0].strip().split()[0].lower() if received_spf[0].strip() else "none"
        return AuthResults(spf=verdict, source="received-spf")

    return AuthResults()


def parse_received_chain(email: ParsedEmail) -> list[Hop]:
    """Return hops in delivery order (origin first), with inter-hop delays."""
    raw_hops = list(reversed(email.header_values("Received")))
    hops: list[Hop] = []
    for i, raw in enumerate(raw_hops):
        flat = " ".join(raw.split())
        clauses, _, date_part = flat.rpartition(";")
        if not _:
            clauses, date_part = flat, ""
        ts = None
        try:
            ts = parsedate_to_datetime(date_part.strip()) if date_part.strip() else None
        except (TypeError, ValueError, IndexError):
            ts = None
        from_m = _FROM_HOST_RE.search(clauses)
        by_m = _BY_HOST_RE.search(clauses)
        by_index = by_m.start() if by_m else len(clauses)
        ips = [ip for ip in _IPV4_RE.findall(clauses[:by_index])]
        hops.append(
            Hop(
                index=i,
                from_host=from_m.group(1) if from_m else "",
                by_host=by_m.group(1).rstrip(";") if by_m else "",
                ip=ips[-1] if ips else "",
                timestamp=ts,
            )
        )
    for prev, cur in itertools.pairwise(hops):
        if prev.timestamp and cur.timestamp:
            try:
                cur.delay_seconds = (cur.timestamp - prev.timestamp).total_seconds()
            except TypeError:  # naive vs aware datetimes
                cur.delay_seconds = None
    return hops


def originating_ip(hops: list[Hop]) -> str:
    """First public IP in the chain: the best guess at the true sending host."""
    for hop in hops:
        if hop.ip and not _is_private(hop.ip):
            return hop.ip
    return ""
