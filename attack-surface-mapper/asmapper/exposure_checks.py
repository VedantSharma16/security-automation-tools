"""Opt-in probe for a curated list of commonly-misconfigured sensitive paths.

This is the only module in the package that issues requests beyond the
initial page fetch, so it is disabled unless explicitly enabled (CLI
``--enable-exposure-checks``, or ``allow_exposure_checks=True`` on
:class:`~asmapper.planner.Planner`). Only run it against targets you are
explicitly authorized to test — it is indistinguishable, from the target's
point of view, from the opening moves of a real attacker doing recon.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urljoin

from .fetcher import fetch
from .models import Finding, Severity

DEFAULT_EXPOSURE_PATHS = Path(__file__).resolve().parent.parent / "data" / "exposure_paths.json"

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def load_exposure_paths(path: Path = DEFAULT_EXPOSURE_PATHS) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def check_exposure_paths(
    base_url: str,
    fetch_fn=fetch,
    paths: list[dict] | None = None,
    delay_seconds: float = 0.0,
) -> list[Finding]:
    paths = load_exposure_paths() if paths is None else paths
    findings: list[Finding] = []

    for entry in paths:
        result = fetch_fn(urljoin(base_url, entry["path"]))
        if delay_seconds:
            time.sleep(delay_seconds)
        if not result.ok:
            continue

        if result.status == 200 and result.body.strip():
            findings.append(
                Finding(
                    id=f"exposure-{entry['path'].strip('/').replace('/', '-')}",
                    title=entry["title"],
                    severity=_SEVERITY_MAP.get(entry.get("severity", "medium"), Severity.MEDIUM),
                    detail=f"{entry['detail']} (GET {entry['path']} returned HTTP 200 with a non-empty body).",
                    category="exposure",
                    recommendation=entry.get("recommendation", "Remove or restrict access to this path."),
                )
            )
        elif result.status in (401, 403):
            findings.append(
                Finding(
                    id=f"exposure-{entry['path'].strip('/').replace('/', '-')}-protected",
                    title=f"{entry['title']} (access-controlled)",
                    severity=Severity.INFO,
                    detail=f"GET {entry['path']} exists but returned HTTP {result.status} — access appears controlled; still worth confirming manually.",
                    category="exposure",
                )
            )

    return findings
