"""Technology fingerprinting from response headers and body via a local signature database."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Severity

DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "data" / "signatures.json"


def load_signatures(path: Path = DEFAULT_SIGNATURES_PATH) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def fingerprint(headers: dict, body: str, signatures: list[dict] | None = None) -> list[Finding]:
    """Match response headers/body against known technology signatures.

    Each match is reported at INFO severity (fingerprinting itself isn't a
    vulnerability) but carries a ``note`` pointing at what to do with the
    identification, e.g. "check the detected version against known CVEs".
    """
    signatures = load_signatures() if signatures is None else signatures
    lower_headers = {k.lower(): (v or "").lower() for k, v in headers.items()}
    body_lower = (body or "").lower()

    findings: list[Finding] = []
    for sig in signatures:
        matched_via = None
        for hs in sig.get("header_signatures", []):
            header_value = lower_headers.get(hs["header"].lower())
            if header_value and hs["contains"].lower() in header_value:
                matched_via = f"header '{hs['header']}'"
                break
        if not matched_via:
            for pattern in sig.get("body_signatures", []):
                if pattern.lower() in body_lower:
                    matched_via = "response body"
                    break
        if matched_via:
            findings.append(
                Finding(
                    id=f"fingerprint-{sig['name'].lower().replace(' ', '-')}",
                    title=f"Detected {sig['category']}: {sig['name']}",
                    severity=Severity.INFO,
                    detail=f"Matched via {matched_via}. {sig.get('note', '')}".strip(),
                    category="fingerprint",
                )
            )
    return findings
