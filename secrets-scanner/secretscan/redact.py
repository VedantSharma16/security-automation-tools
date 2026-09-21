"""Redacting matched secrets before they land in a report.

A secrets scanner that prints the full secret it just found defeats its own
purpose — the JSON/SARIF report is exactly the kind of artifact that ends up
attached to a CI log or a ticket. Every finding is redacted before it leaves
the scanner.
"""

from __future__ import annotations


def redact(value: str, keep: int = 4) -> str:
    """Mask the middle of ``value``, keeping a few characters at each end.

    >>> redact("AKIAIOSFODNN7EXAMPLE")
    'AKIA...MPLE'
    >>> redact("short")
    '*****'
    """
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"
