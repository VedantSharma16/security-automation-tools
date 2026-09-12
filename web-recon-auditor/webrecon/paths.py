"""Sensitive-path probing with soft-404 baselining.

Many applications respond HTTP 200 (with a catch-all "not found" page) for
*any* unmatched route. Naively flagging every 200 response as "exposed"
would make every scan a wall of false positives. Instead we first probe a
random, guaranteed-nonexistent path to learn the host's "not found" shape,
then only flag a sensitive path as a real hit when its response looks
meaningfully different from that baseline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .fetcher import FetchResult, Fetcher
from .findings import Finding

# A response within this fraction of the baseline's content length is
# treated as "the same soft-404 page", not a real hit.
_LENGTH_SIMILARITY_THRESHOLD = 0.10

DEFAULT_PATH_RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "sensitive_paths.txt"


@dataclass
class PathRule:
    severity: str
    path: str
    title: str


def load_path_rules(path: str | Path = DEFAULT_PATH_RULES_PATH) -> list[PathRule]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()

    rules = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        severity, rule_path, title = line.split("|", 2)
        rules.append(PathRule(severity=severity, path=rule_path, title=title))
    return rules


def _looks_like_baseline(result: FetchResult, baseline: FetchResult) -> bool:
    if not baseline.ok or not result.ok:
        return False
    if result.status_code != baseline.status_code:
        return False
    if baseline.content_length == 0:
        return result.content_length == 0
    diff_ratio = abs(result.content_length - baseline.content_length) / baseline.content_length
    return diff_ratio <= _LENGTH_SIMILARITY_THRESHOLD


def probe_sensitive_paths(
    fetcher: Fetcher, base_url: str, rules: list[PathRule] | None = None
) -> list[Finding]:
    rules = rules if rules is not None else load_path_rules()
    baseline = fetcher.baseline_404(base_url)

    findings: list[Finding] = []
    for rule in rules:
        result = fetcher.get_path(base_url, rule.path)
        if not result.ok or result.status_code is None:
            continue
        if result.status_code >= 400:
            continue
        if _looks_like_baseline(result, baseline):
            continue
        findings.append(
            Finding(
                id=f"exposed-path-{rule.path.strip('/').replace('/', '-')}",
                category="paths",
                severity=rule.severity,
                title=rule.title,
                detail=f"GET /{rule.path.lstrip('/')} returned HTTP "
                f"{result.status_code} ({result.content_length} bytes), distinct "
                f"from this host's baseline 404 response "
                f"(HTTP {baseline.status_code}, {baseline.content_length} bytes).",
                recommendation="Remove or restrict access to this path (auth, "
                "firewall rule, or deletion from the deployed artifact).",
                evidence={"path": rule.path, "status_code": result.status_code},
            )
        )

    findings += check_security_txt(fetcher, base_url)
    return findings


def check_security_txt(fetcher: Fetcher, base_url: str) -> list[Finding]:
    """RFC 9116: absence is informational, not a vulnerability — but recruiters
    and real pentest checklists both look for it, so it's worth surfacing."""
    result = fetcher.get_path(base_url, ".well-known/security.txt")
    if result.ok and result.status_code == 200 and result.content_length > 0:
        return []
    return [
        Finding(
            id="missing-security-txt",
            category="paths",
            severity="info",
            title="No /.well-known/security.txt published",
            detail="RFC 9116 security.txt was not found, so there is no "
            "documented channel for a researcher to responsibly report a "
            "vulnerability to this organization.",
            recommendation="Publish a /.well-known/security.txt with a contact "
            "and (ideally) a PGP key and disclosure policy URL.",
        )
    ]
