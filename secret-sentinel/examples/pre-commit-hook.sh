#!/usr/bin/env bash
# Example git pre-commit hook: block a commit if it would introduce a secret.
#
# Install with:
#   cp examples/pre-commit-hook.sh /path/to/repo/.git/hooks/pre-commit
#   chmod +x /path/to/repo/.git/hooks/pre-commit
#
# Scans only the working tree (staged-and-unstaged state) at min-severity
# medium and above; tune as needed. Exits non-zero (blocking the commit)
# whenever a finding is reported.

set -euo pipefail

secret-sentinel . --min-severity medium --no-color
