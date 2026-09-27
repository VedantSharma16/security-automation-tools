"""secret-scanner: git-aware credential leak detection.

Scans a working tree and (optionally) full git history for hardcoded
secrets, using known-provider signatures plus Shannon-entropy heuristics
for anything that doesn't match a named format.
"""

__version__ = "0.1.0"
