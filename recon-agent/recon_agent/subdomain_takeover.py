"""Dangling-CNAME subdomain takeover detection.

A subdomain takeover happens when a DNS record (typically a CNAME) still
points at a third-party service (GitHub Pages, S3, Heroku, ...) after the
resource on that service has been deleted or was never claimed. An attacker
who registers the same name on that provider then serves content from the
victim's own subdomain - a classic, still-common finding in bug bounty and
external attack-surface assessments.

Detection is two-staged, same defence-in-depth idea as the rest of the repo:
  1. Does any hop in the CNAME chain match a known vulnerable-provider
     pattern (`data/takeover_fingerprints.json`)?
  2. If so, fetch the page and look for that provider's "unclaimed resource"
     error text to confirm rather than just flag a coincidental CNAME.

Both the DNS lookup and the HTTP fetch are injectable, stdlib-only, and
never raise - a failure degrades to "unconfirmed" rather than crashing the
agent loop.
"""

from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.request import Request, urlopen

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

with open(os.path.join(_DATA_DIR, "takeover_fingerprints.json"), encoding="utf-8") as _fh:
    FINGERPRINTS: list[dict] = json.load(_fh)

_MAX_BODY_BYTES = 20_000

CnameResolver = Callable[[str], list[str]]
BodyFetcher = Callable[[str, float], str]


def default_cname_resolver(hostname: str) -> list[str]:
    """Return the CNAME/alias chain for `hostname` (empty if it doesn't resolve).

    `socket.gethostbyname_ex` is the only CNAME-chain-aware lookup available
    in the standard library; its `aliaslist` holds the intermediate names a
    resolver walked through (including the final canonical name when it
    differs from the queried name), which is exactly the "what does this
    subdomain point at" data a takeover check needs.
    """
    try:
        canonical, aliases, _ips = socket.gethostbyname_ex(hostname)
    except OSError:
        return []
    chain = list(aliases)
    if canonical and canonical != hostname and canonical not in chain:
        chain.append(canonical)
    return chain


def default_body_fetcher(url: str, timeout: float) -> str:
    request = Request(url, headers={"User-Agent": "recon-agent/0.1 (authorized-assessment)"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - deliberate recon request
        return response.read(_MAX_BODY_BYTES).decode(errors="replace")


@dataclass(frozen=True)
class TakeoverResult:
    subdomain: str
    status: str  # "vulnerable" | "possible" | "not_vulnerable"
    provider: str | None
    cname: str | None
    confirmed: bool
    detail: str

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "status": self.status,
            "provider": self.provider,
            "cname": self.cname,
            "confirmed": self.confirmed,
            "detail": self.detail,
        }


def _matching_fingerprint(chain: list[str]) -> tuple[dict, str] | None:
    for hop in chain:
        lowered = hop.lower()
        for fingerprint in FINGERPRINTS:
            if fingerprint["cname_pattern"] in lowered:
                return fingerprint, hop
    return None


def check_takeover(
    subdomain: str,
    cname_resolver: CnameResolver = default_cname_resolver,
    body_fetcher: BodyFetcher = default_body_fetcher,
    timeout: float = 5.0,
) -> TakeoverResult:
    """Check a single subdomain for a dangling CNAME pointing at a known-vulnerable provider."""
    chain = cname_resolver(subdomain)
    match = _matching_fingerprint(chain)
    if match is None:
        return TakeoverResult(
            subdomain=subdomain,
            status="not_vulnerable",
            provider=None,
            cname=None,
            confirmed=False,
            detail="No CNAME matched a known vulnerable-provider pattern.",
        )

    fingerprint, cname = match
    provider = fingerprint["provider"]

    body = ""
    for scheme in ("https", "http"):
        try:
            body = body_fetcher(f"{scheme}://{subdomain}/", timeout)
            break
        except Exception:
            continue

    if fingerprint["fingerprint_text"] in body:
        return TakeoverResult(
            subdomain=subdomain,
            status="vulnerable",
            provider=provider,
            cname=cname,
            confirmed=True,
            detail=(
                f"CNAME points at {provider} ({cname}) and the response body matches the provider's "
                f"'unclaimed resource' error page. This subdomain is very likely takeover-able: register "
                f"the matching resource on {provider} to claim it before an attacker does."
            ),
        )

    return TakeoverResult(
        subdomain=subdomain,
        status="possible",
        provider=provider,
        cname=cname,
        confirmed=False,
        detail=(
            f"CNAME points at {provider} ({cname}), a service known to allow subdomain takeover via "
            f"dangling CNAMEs, but the confirming error page was not observed (the resource may still be "
            f"claimed, or the page was unreachable). Manually verify before treating this as exploitable."
        ),
    )


def scan_for_takeover(
    subdomains: list[str],
    cname_resolver: CnameResolver = default_cname_resolver,
    body_fetcher: BodyFetcher = default_body_fetcher,
    timeout: float = 5.0,
) -> list[TakeoverResult]:
    """Check every subdomain in `subdomains` and return only the flagged (vulnerable/possible) ones."""
    flagged = []
    for subdomain in subdomains:
        result = check_takeover(subdomain, cname_resolver=cname_resolver, body_fetcher=body_fetcher, timeout=timeout)
        if result.status != "not_vulnerable":
            flagged.append(result)
    return flagged
