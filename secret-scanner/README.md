# secretscan

An offline secret/credential leak scanner for source trees and full git
history - the kind of check that belongs in a pre-commit hook or a CI
gate before code (or a merge) ships. Think a small, from-scratch
`gitleaks`/`detect-secrets`: no dependencies, no network calls, and no
telemetry - it never needs to see your code leave your machine.

## Why this exists

Log/IOC/process triage tools (see the rest of this repo) answer "did
something bad already happen?" This tool answers a different, earlier
question: "are we about to ship a credential we shouldn't?" That's a
distinct, everyday DevSecOps/AppSec problem, and it rounds out the
portfolio with a preventive control instead of another detective one.

## What it detects

| Category | Examples | Severity |
|---|---|---|
| Vendor-format tokens | AWS access key ID / secret key, GitHub PAT (classic + fine-grained), Slack token/webhook, Google API key, Stripe live key, Twilio API key, JWT | MEDIUM-CRITICAL |
| Private key material | PEM `-----BEGIN ... PRIVATE KEY-----` blocks | CRITICAL |
| Generic secrets | `<keyword> = "<high-entropy value>"` for `api_key`, `secret`, `token`, `password`, etc. - a Shannon-entropy heuristic fallback for anything that doesn't match a known vendor format | MEDIUM |

Named vendor rules are regex-matched against the exact token shape
(precise, low false-positive rate). The generic rule only runs on a line
when no named rule already explains it, requires a keyword-adjacent
quoted assignment, an alphanumeric mix, and an entropy floor
(default 3.5 bits/char), and skips an explicit placeholder denylist
(`changeme`, `your_api_key`, `<...>`, `{{...}}`, etc.) - it's a genuine
heuristic and the tradeoff (some noise, in exchange for catching secrets
with no fixed format) is the same one every scanner like this makes.

Every match is redacted before it's ever printed or written to a report
(`AKIA…MPLE`, never the full value).

## Two scan modes

- **Working tree** (default): walks the current files on disk.
- **`--include-git`**: additionally walks every commit's diff
  (`git show --unified=0`) across the *entire* history, so a secret that
  was committed and later deleted is still caught - a plain file scan by
  definition can never see it, but it's still sitting in `.git/` for
  anyone who clones the repo.

## Baseline workflow (avoiding alert fatigue)

A fresh scan of any real repo tends to turn up intentional
non-secrets (test fixtures, documented example credentials like AWS's own
`AKIAIOSFODNN7EXAMPLE`). Re-litigating those on every CI run trains
people to ignore the tool. So, same pattern as `detect-secrets`:

```bash
secretscan baseline <path> --out .secretscan-baseline.json   # accept current findings
secretscan scan <path> --baseline .secretscan-baseline.json  # only NEW findings fail
```

A baseline is scoped to the exact `(rule, file, value)` fingerprint, so
it survives unrelated line-number churn but still catches a *genuinely
new* secret dropped into an already-reviewed file. Note: generate and
consume a baseline from the same root path - fingerprints include the
file path relative to whatever root you pass, so a baseline built from
`secretscan baseline .` won't line up with `secretscan scan subdir/`.

This repo ships `.secretscan-baseline.json`, generated from this
project's own test fixtures (which intentionally contain fake secrets to
exercise every rule). See it in action below.

## Install

```bash
cd secret-scanner
pip install -e .          # core tool, zero runtime dependencies
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
# Try it against the bundled demo file (a real-format, fake AWS key):
secretscan scan examples/sample_leaky_file.py

# Scan this whole project, with the checked-in baseline suppressing the
# intentional test fixtures - only the demo secret above should surface:
secretscan scan . --baseline .secretscan-baseline.json

# Full git history too, not just the working tree:
secretscan scan . --include-git --baseline .secretscan-baseline.json

# Machine-readable output for CI:
secretscan scan . --format json --out report.json
```

Exit codes (CI-friendly): `0` clean, `1` new (non-baselined) findings
found, `2` the scan itself failed (bad path, git error).

### CI example

```yaml
# .github/workflows/secretscan.yml
- name: Scan for leaked secrets
  run: |
    pip install -e secret-scanner
    secretscan scan . --include-git --baseline secret-scanner/.secretscan-baseline.json
```

## Architecture

```
secretscan/
  rules.py       vendor regex rules + Shannon-entropy generic fallback
  scanner.py     working-tree file walk + git-history diff walk -> Finding list
  baseline.py    fingerprint-based accept-list: generate / load
  report.py      Finding list -> JSON or aligned table, with severity summary
  cli.py         argparse: `scan` and `baseline` subcommands
```

Each stage is a pure function over the previous stage's output, so every
piece is independently unit-tested - including a git-history test that
creates a real temporary repo, commits a secret, removes it in a later
commit, and asserts the working-tree scan misses it while the git-history
scan still catches it.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

60 tests covering every rule's regex, the entropy heuristic and its
placeholder denylist, file discovery (binary/vendor-dir skipping), git
history parsing, baseline generation/round-trip/suppression, report
rendering, and the CLI end-to-end (including exit codes).

## Known limitations

- Regex/entropy detection, not secret *validation* - it never calls out
  to AWS/GitHub/etc. to check if a matched key is still live. That's a
  deliberate scope boundary: this tool tells you what to rotate, not
  whether you still need to.
- The generic entropy rule is a heuristic; expect occasional false
  positives on genuinely random-looking non-secrets (this is inherent to
  every tool in this category, not specific to this implementation).
- Git history scanning shells out to `git` and walks every commit's
  diff - on a very large repo, pair `--max-commits` with a scheduled
  full scan rather than running it unbounded on every push.
