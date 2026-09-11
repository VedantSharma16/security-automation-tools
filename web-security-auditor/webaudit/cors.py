"""CORS misconfiguration detection.

The technique: re-request the target with an arbitrary, attacker-controlled
``Origin`` header and see whether the server reflects it back in
``Access-Control-Allow-Origin`` — especially alongside
``Access-Control-Allow-Credentials: true``, which would let any third-party
site read authenticated responses on behalf of a logged-in victim.
"""

from __future__ import annotations

from .models import CheckResult


def analyze_cors(probe_headers: dict, probe_origin: str) -> list[CheckResult]:
    acao = probe_headers.get("access-control-allow-origin", "").strip()
    acac = probe_headers.get("access-control-allow-credentials", "").strip().lower() == "true"

    if not acao:
        return [CheckResult(
            "cors", "cors", "pass", "info", "CORS",
            "No Access-Control-Allow-Origin returned for an arbitrary cross-origin probe.",
            None,
        )]

    if acao == "*":
        if acac:
            return [CheckResult(
                "cors", "cors", "fail", "high", "CORS",
                "Access-Control-Allow-Origin is '*' together with "
                "Access-Control-Allow-Credentials: true. Browsers reject this exact "
                "combination, but it signals a broken origin policy on the server.",
                "Return a specific allow-listed origin instead of '*' whenever "
                "credentials are allowed.",
            )]
        return [CheckResult(
            "cors", "cors", "info", "info", "CORS",
            "Access-Control-Allow-Origin is '*' (no credentials allowed).",
            "Fine for a fully public, unauthenticated API; scope it down otherwise.",
        )]

    if acao == probe_origin:
        severity = "critical" if acac else "high"
        credential_note = " with credentials allowed" if acac else ""
        return [CheckResult(
            "cors", "cors", "fail", severity, "CORS",
            f"Access-Control-Allow-Origin reflects an arbitrary request Origin "
            f"('{probe_origin}'){credential_note}.",
            "Validate Origin against an explicit server-side allow-list instead of "
            "reflecting whatever Origin the client sends.",
        )]

    return [CheckResult(
        "cors", "cors", "pass", "info", "CORS",
        f"Access-Control-Allow-Origin ('{acao}') does not reflect the probe origin; "
        "looks allow-listed.",
        None,
    )]
