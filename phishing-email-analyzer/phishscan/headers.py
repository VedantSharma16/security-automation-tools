"""Header analysis: sender consistency and SPF/DKIM/DMARC results."""
from __future__ import annotations

import re
from email.message import Message
from email.utils import getaddresses

from .models import Finding
from .urls import _lookalike

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.I)
_FAIL = {"fail", "softfail", "none", "permerror", "temperror", "neutral"}


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower().rstrip(">") if "@" in addr else ""


def _addr(msg: Message, name: str) -> tuple[str, str]:
    """Return (display_name, address) of the first entry in a header."""
    pairs = getaddresses([str(v) for v in msg.get_all(name, [])])
    return pairs[0] if pairs else ("", "")


def auth_results(msg: Message) -> dict[str, str]:
    """Parse the Authentication-Results header(s) into {mechanism: result}."""
    out: dict[str, str] = {}
    for hdr in msg.get_all("Authentication-Results", []):
        for mech, res in _AUTH_RE.findall(str(hdr)):
            out.setdefault(mech.lower(), res.lower())
    return out


def analyze_headers(msg: Message) -> list[Finding]:
    findings: list[Finding] = []
    name, from_addr = _addr(msg, "From")
    from_dom = _domain(from_addr)

    hit = _lookalike(from_dom) if from_dom else None
    if hit:
        findings.append(Finding("sender", "high",
                                f"Sender domain impersonates {hit[0]} (legit: {hit[1]})",
                                from_addr, "T1656"))

    results = auth_results(msg)
    if not results:
        findings.append(Finding("auth", "low",
                                "No Authentication-Results header; sender authentication unverifiable"))
    for mech in ("spf", "dkim", "dmarc"):
        res = results.get(mech)
        if res in _FAIL:
            sev = "high" if mech == "dmarc" or res == "fail" else "medium"
            findings.append(Finding("auth", sev, f"{mech.upper()} result: {res}",
                                    f"Authentication-Results {mech}={res}", "T1566"))

    _, reply = _addr(msg, "Reply-To")
    if reply and from_dom and _domain(reply) != from_dom:
        findings.append(Finding("sender", "medium",
                                "Reply-To domain differs from From domain",
                                f"From={from_addr} Reply-To={reply}", "T1566.001"))

    _, rpath = _addr(msg, "Return-Path")
    if rpath and from_dom and _domain(rpath) != from_dom:
        findings.append(Finding("sender", "low",
                                "Return-Path domain differs from From domain",
                                f"From={from_addr} Return-Path={rpath}"))

    # Display name impersonating an address that is not the real sender
    m = re.search(r"[\w.+-]+@[\w.-]+", name)
    if m and _domain(m.group()) != from_dom:
        findings.append(Finding("sender", "high",
                                "Display name contains a different email address",
                                f"{name!r} <{from_addr}>", "T1656"))

    if len(msg.get_all("Received", [])) == 0:
        findings.append(Finding("sender", "low", "No Received headers (possibly synthetic or stripped)"))
    return findings
