"""Individual, independently testable security checks.

Each check module exposes a single ``check_*(target, ...) -> list[Finding]``
function that operates on already-fetched data (a ``ScanTarget`` or
``TLSInfo``). None of them perform network I/O themselves, which keeps them
fast and deterministic to unit test.
"""
