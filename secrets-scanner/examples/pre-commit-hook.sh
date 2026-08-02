#!/usr/bin/env bash
# Example git pre-commit hook: block a commit if it introduces a new secret.
#
# Install:
#   cp examples/pre-commit-hook.sh /path/to/repo/.git/hooks/pre-commit
#   chmod +x /path/to/repo/.git/hooks/pre-commit
#
# Review any findings once, then bake known-safe ones into a baseline so
# they don't block future commits:
#   secretscan . --update-baseline --baseline .secretscan-baseline.json
#   git add .secretscan-baseline.json

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
BASELINE="$REPO_ROOT/.secretscan-baseline.json"

BASELINE_ARGS=()
if [ -f "$BASELINE" ]; then
  BASELINE_ARGS=(--baseline "$BASELINE")
fi

if ! secretscan "$REPO_ROOT" --min-severity medium "${BASELINE_ARGS[@]}" --no-color; then
  echo ""
  echo "pre-commit: secretscan found likely secret(s) above -- commit blocked." >&2
  echo "Fix them, or if a finding is a confirmed false positive, add it to" >&2
  echo "$BASELINE with: secretscan . --update-baseline --baseline $BASELINE" >&2
  exit 1
fi
