# Secrets Scanner

A git-aware secret-detection tool: it scans a working tree (and optionally
the full commit history) for hardcoded credentials using vendor-specific
regex signatures plus generic Shannon-entropy detection, supports
baseline/allowlist suppression for reviewed false positives, and can
optionally use an LLM to triage ambiguous findings — with a fully offline,
deterministic fallback when no API key is configured.

## Why this exists

Leaked credentials are one of the most common, most preventable causes of
real breaches — an API key committed to a public repo, a database password
left in a config file, a token that outlives the commit that "removed" it
because it's still sitting in git history. This is a from-scratch
implementation of the core detection model behind tools like gitleaks and
truffleHog (signature + entropy detection, git history scanning, baseline
suppression), built as a self-contained demonstration of that model for
DevSecOps/AppSec-style work: know what secrets are in a codebase — past and
present — before an attacker finds them.

## Features

- **Signature detection** — 20 regex rules for well-known secret formats
  (AWS keys, GitHub/GitLab/npm tokens, Stripe/SendGrid/Twilio keys, Slack
  tokens and webhooks, PEM private key blocks, JWTs, database connection
  strings with embedded credentials, and generic API-key/password
  assignments), each with a severity and category.
- **Entropy detection** — flags high-entropy values assigned to
  suspiciously named variables (`*_key`, `*_token`, `*_secret`,
  `password`, ...) that don't match a known vendor format, while filtering
  out placeholders (`changeme`, `<your-key-here>`, `${VAR}`) and
  low-diversity strings. Both signals — suspicious name *and* high entropy
  — are required, which keeps the false-positive rate manageable.
- **Git history scanning** (`--git-history`) — parses `git log -p` to scan
  every line ever *added* to the repo, so a secret that was committed and
  later deleted from the working tree is still caught. Rotating the
  credential is the only real fix for that; a working-tree-only scan can't
  even see it.
- **Baseline suppression** (`--baseline` / `--update-baseline`) — after a
  human reviews a scan and confirms certain findings are false positives
  (test fixtures, intentionally fake examples), their fingerprints are
  written to a baseline file; future scans stay quiet about them.
  Fingerprints only — no secret contents are ever persisted in a baseline.
- **Findings are redacted at the source** — a matched secret is masked
  (`AKIA****MNOP`) the moment it's found and reduced to a hash-based
  fingerprint; the raw value is never stored on a `Finding`, never printed,
  and never written to a JSON report or baseline file.
- **Optional LLM triage** (`--triage`) — for ambiguous, entropy-only
  findings, an LLM call (Claude, via `ANTHROPIC_API_KEY`) classifies the
  finding as `likely_secret` / `likely_false_positive` / `uncertain` from
  redacted metadata only (file path, category, entropy score, masked
  preview) — the raw secret is never sent anywhere. Vendor-format matches
  skip the LLM call entirely (offline heuristic is already confident) to
  save cost. Without an API key, a deterministic offline heuristic runs
  instead, so the tool and its tests work fully offline.
- **Automation-friendly** — JSON reports, `--min-severity` filtering, and
  exit codes (`0` clean / `1` findings / `2` error) suitable for a
  pre-commit hook or CI gate (`examples/pre-commit-hook.sh`).
- 61 unit tests, including a real temporary git repository exercised
  end-to-end for the history-scanning tests (no mocked `git` output).

## Installation

```bash
cd secrets-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Scan the current directory
python -m secretscan.cli .

# Try it on the bundled (fake) vulnerable sample
python -m secretscan.cli examples/vulnerable_sample --no-color

# Generate a couple of additional (gitignored, local-only) demo secrets --
# Stripe/Slack formats are realistic enough to trip GitHub's own push
# protection, so they're built at runtime rather than committed literally.
python examples/generate_demo_secrets.py
python -m secretscan.cli examples/vulnerable_sample/generated_config.py --no-color

# Only show high/critical findings, write a JSON report
python -m secretscan.cli . --min-severity high --json-out report.json

# Also scan the full commit history of a git repo (catches deleted secrets)
python -m secretscan.cli . --git-history

# Limit history scan to the last 200 commits, across all branches
python -m secretscan.cli . --git-history --max-commits 200 --all-branches

# Record a baseline of currently known findings (e.g. after manual review)
python -m secretscan.cli . --baseline .secretscan-baseline.json --update-baseline

# Later: scan and suppress anything already in the baseline
python -m secretscan.cli . --baseline .secretscan-baseline.json

# Annotate findings with a likely-secret / false-positive verdict
python -m secretscan.cli . --triage   # uses ANTHROPIC_API_KEY if set, else offline heuristic

# Disable the entropy detector, keep only vendor-format signatures
python -m secretscan.cli . --no-entropy
```

Exit codes: `0` = no findings (after `--min-severity` filtering), `1` =
findings reported, `2` = a fatal error (e.g. malformed rule file).

See `examples/pre-commit-hook.sh` for wiring this into a git pre-commit hook.

## Rule format

```yaml
- id: aws-access-key-id
  pattern: '(?<![A-Z0-9])A(?:KIA|SIA|ROA|IDA)[0-9A-Z]{16}(?![A-Z0-9])'
  severity: critical
  category: cloud
  description: AWS Access Key ID (static or STS-issued).
```

`pattern` is matched against each scanned line. The bundled
[`rules/default_rules.yaml`](rules/default_rules.yaml) covers 20 signatures
across cloud (AWS/GCP/Heroku), VCS (GitHub/GitLab), payments (Stripe),
messaging (Slack/SendGrid/Twilio), package registries (npm), crypto (PEM
private keys), auth (JWTs), databases, and generic key/password
assignments.

## Project layout

```
secrets-scanner/
├── secretscan/
│   ├── rules.py         # YAML rule loading/validation, regex matching
│   ├── entropy.py         # Shannon entropy + suspicious-key-name detection
│   ├── scanner.py           # working-tree file walking, redaction, fingerprinting
│   ├── git_scanner.py         # git log -p parsing for history scanning
│   ├── baseline.py              # baseline load/save/suppression
│   ├── triage.py                  # optional LLM triage with offline fallback
│   ├── report.py                    # console + JSON report rendering
│   └── cli.py                         # argparse entry point
├── rules/
│   └── default_rules.yaml
├── examples/
│   ├── vulnerable_sample/           # fake secrets for demoing detection
│   ├── generate_demo_secrets.py       # builds 2 more demo secrets locally (gitignored)
│   └── pre-commit-hook.sh               # CI/pre-commit integration example
├── tests/
│   ├── test_rules.py, test_entropy.py, test_scanner.py, test_git_scanner.py,
│   └── test_baseline.py, test_triage.py, test_report.py, test_cli.py
├── requirements.txt
└── requirements-dev.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Possible extensions

- Detect and warn on secrets inside binary/archive files (currently
  skipped) by unpacking common archive formats before scanning.
- Add a `--fail-on-new` mode for CI that only fails when a finding's
  fingerprint isn't already in the baseline *and* wasn't present before
  the current diff, instead of failing on the full repo state.
- Ship a Docker image scanning mode (scan built image layers, not just
  source).
