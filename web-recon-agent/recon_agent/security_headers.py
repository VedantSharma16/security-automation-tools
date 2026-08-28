"""Grading logic for HTTP response security headers.

Pure and network-free: given a headers dict and the scheme the response was
served over, decide which hardening headers are missing or misconfigured.
Kept separate from ``tools.py`` so it's trivially unit-testable without any
HTTP involved.
"""

from __future__ import annotations

from .severity import WEIGHTS

HEADER_SPECS = [
    {
        "header": "Strict-Transport-Security",
        "https_only": True,
        "severity": "high",
        "advice": "Send HSTS with a long max-age to prevent protocol-downgrade "
        "and cookie-hijacking attacks.",
    },
    {
        "header": "Content-Security-Policy",
        "https_only": False,
        "severity": "high",
        "advice": "Define a CSP to reduce the blast radius of any XSS that does "
        "get through.",
    },
    {
        "header": "X-Content-Type-Options",
        "https_only": False,
        "severity": "medium",
        "expected": "nosniff",
        "advice": "Set 'X-Content-Type-Options: nosniff' to stop browsers from "
        "MIME-sniffing responses.",
    },
    {
        "header": "X-Frame-Options",
        "https_only": False,
        "severity": "medium",
        "advice": "Set X-Frame-Options (or a CSP frame-ancestors directive) to "
        "mitigate clickjacking.",
    },
    {
        "header": "Referrer-Policy",
        "https_only": False,
        "severity": "low",
        "advice": "Set a Referrer-Policy to avoid leaking full URLs (tokens, "
        "internal paths) to third parties.",
    },
    {
        "header": "Permissions-Policy",
        "https_only": False,
        "severity": "low",
        "advice": "Set a Permissions-Policy to explicitly disable powerful "
        "browser features the app doesn't use.",
    },
]

INFO_DISCLOSURE_HEADERS = ["server", "x-powered-by"]


def grade(headers: dict, scheme: str = "https") -> dict:
    """Grade a response's security headers.

    Returns a dict with a 0-100 ``score``, a ``missing`` list (each item has
    ``header``/``severity``/``advice``), a ``present`` list, and any
    information-disclosure headers observed.
    """
    normalized = {k.lower(): v for k, v in headers.items()}

    missing = []
    present = []
    for spec in HEADER_SPECS:
        if spec["https_only"] and scheme != "https":
            continue
        key = spec["header"].lower()
        if key not in normalized:
            missing.append(
                {"header": spec["header"], "severity": spec["severity"], "advice": spec["advice"]}
            )
            continue
        value = normalized[key]
        expected = spec.get("expected")
        if expected and expected.lower() not in value.lower():
            missing.append(
                {
                    "header": spec["header"],
                    "severity": spec["severity"],
                    "advice": f"{spec['advice']} (found '{value}', expected to include '{expected}')",
                }
            )
            continue
        present.append({"header": spec["header"], "value": value})

    info_disclosure = [
        {"header": name, "value": normalized[name]} for name in INFO_DISCLOSURE_HEADERS if name in normalized
    ]

    score = 100
    for item in missing:
        score -= WEIGHTS.get(item["severity"], 0)
    score = max(score, 0)

    return {
        "score": score,
        "missing": missing,
        "present": present,
        "info_disclosure": info_disclosure,
        "scheme": scheme,
    }
