"""Load canned probe results so the agent can run without touching the network.

Useful for demos, CI, and offline development: point `--fixture` at a JSON
file shaped like `examples/fixture_example.json` and the agent runs its
normal decision loop against those canned results instead of live sockets.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import ProbeResult, TLSResult


def load_fixture(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def make_probe_url_fn(fixture: dict):
    def _probe_url(url: str, timeout: float = 5.0) -> ProbeResult:
        scheme = "https" if url.startswith("https://") else "http"
        data = fixture.get(scheme)
        if data is None:
            return ProbeResult(url=url, ok=False, error="no fixture data for this scheme")
        return ProbeResult(
            url=url,
            ok=data.get("ok", True),
            status_code=data.get("status_code"),
            headers=data.get("headers", {}),
            elapsed_ms=data.get("elapsed_ms"),
            error=data.get("error"),
        )

    return _probe_url


def make_probe_tls_fn(fixture: dict):
    def _probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> TLSResult:
        data = fixture.get("tls")
        if data is None:
            return TLSResult(host=host, port=port, ok=False, error="no fixture data for tls")
        return TLSResult(
            host=host,
            port=port,
            ok=data.get("ok", True),
            version=data.get("version"),
            not_after=data.get("not_after"),
            days_until_expiry=data.get("days_until_expiry"),
            issuer=data.get("issuer"),
            error=data.get("error"),
        )

    return _probe_tls
