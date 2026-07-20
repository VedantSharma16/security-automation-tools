# Secret Scanner

A git-friendly, offline static-analysis tool that scans a directory tree
for hardcoded credentials — vendor API keys, private keys, database
connection strings, and generic high-entropy secrets — before they get
merged, deployed, or pushed to a public repo.

It's the same class of tool as [gitleaks](https://github.com/gitleaks/gitleaks)
or [trufflehog](https://github.com/trufflesecurity/trufflehog): a signature
rule engine layered with entropy-based detection for secrets that don't
match a known vendor format, plus baseline suppression and SARIF output so
it slots straight into a CI pipeline or GitHub code scanning.

## Why this exists

Leaked credentials are one of the most common — and most preventable —
root causes of real breaches: a hardcoded AWS key in a public repo, a
Stripe key in a Slack export, a `.env` file committed by accident. AppSec
and platform-security teams run tools exactly like this one as a pre-commit
hook and a CI gate. This is a from-scratch implementation of that model:
no SaaS dependency, runs fully offline, and is small enough to read
end-to-end in one sitting.

## Features

- **16 built-in signature rules** — AWS access/secret keys, GitHub tokens
  (classic + fine-grained), Slack bot tokens and incoming webhooks, Google
  API keys, Stripe live/restricted keys, Twilio API keys, npm tokens,
  PEM-encoded private key blocks, JWTs, and hardcoded database/AMQP
  connection strings.
- **Entropy-based generic detection** — for secrets with no fixed format
  (`api_key = "..."`, `password = "..."`), a Shannon-entropy check on the
  assigned value catches real secrets while a placeholder heuristic filters
  out `changeme`, `your_key_here`, `<INSERT_SECRET>`, and similar dummy
  values so the rule doesn't fire on every config template.
- **Specific-over-generic dedup** — when a line trips both a vendor
  signature and the generic entropy rule for the same value (e.g.
  `STRIPE_SECRET_KEY = "sk_live_..."`), only the more informative,
  vendor-specific finding is reported.
- **Baseline suppression** — snapshot the fingerprints of
  currently-accepted findings (`--baseline file --update-baseline`) so
  future scans in CI only fail on genuinely *new* secrets, the same
  triage-once model gitleaks/trufflehog use.
- **Binary/vendor-directory aware** — skips `.git`, `node_modules`,
  virtualenvs, build output, and anything that looks binary, so a scan of
  a real repo doesn't choke on compiled assets or dependency trees.
- **JSON, SARIF, and colored console output** — SARIF output is ready to
  upload directly to GitHub code scanning (`--sarif-out results.sarif`).
- **CI-friendly exit codes** — `--fail-on` sets the severity threshold
  that actually fails the build, independent of `--min-severity`, which
  only controls what's *shown*. That lets a pipeline print every finding
  for visibility while only blocking merges on `high`/`critical`.
- 72 unit tests covering entropy scoring, every bundled rule's true
  positives and false-positive suppression, filesystem walking/exclusion,
  baseline diffing, JSON/SARIF report generation, and the CLI end-to-end.

## Installation

```bash
cd secret-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Scan the current directory with the bundled rule set
python -m secretscanner.cli .

# Generate and scan the bundled demo repo (synthetic secrets only, generated
# locally rather than committed — see examples/README.md for why)
python examples/generate_demo.py
python -m secretscanner.cli examples/vulnerable_repo

# Only fail the build on high/critical findings; still show everything
python -m secretscanner.cli . --fail-on high

# Write JSON and SARIF reports (for GitHub code scanning)
python -m secretscanner.cli . --json-out report.json --sarif-out report.sarif

# Exclude a directory/glob beyond the built-in defaults
python -m secretscanner.cli . --exclude 'fixtures/*' --exclude '*.snap'

# Record a baseline of currently-accepted findings
python -m secretscanner.cli . --baseline baseline.json --update-baseline

# Later: only new findings since that baseline fail the scan
python -m secretscanner.cli . --baseline baseline.json

# Use a custom rule file instead of the bundled defaults
python -m secretscanner.cli . --rules my_rules.yaml
```

Exit codes: `0` = no findings at/above `--fail-on` (default: any finding),
`1` = qualifying findings present, `2` = a fatal error (e.g. missing scan
path).

## Rule format

```yaml
- id: stripe-live-secret-key
  pattern: 'sk_live_[0-9A-Za-z]{24,}'
  severity: critical
  category: Stripe
  description: Stripe live-mode secret key.
```

Set `entropy_check: true` for a generic `name = value`-shaped rule where
only the *name* is known ahead of time (`api_key`, `password`, ...) — the
pattern's first capture group is treated as the candidate secret and only
reported if it also passes a Shannon-entropy threshold:

```yaml
- id: generic-secret-assignment
  pattern: '(?i)(?:api[_-]?key|client[_-]?secret|secret[_-]?key)\s*[:=]\s*["'']?([A-Za-z0-9+/_\-\.=]{16,})["'']?'
  severity: medium
  category: Generic
  entropy_check: true
```

The bundled [`rules/default_rules.yaml`](rules/default_rules.yaml) has the
full set with descriptions.

## Project layout

```
secret-scanner/
├── secretscanner/
│   ├── entropy.py     # Shannon entropy + placeholder-value heuristics
│   ├── rules.py        # YAML rule loading/validation, regex + entropy matching
│   ├── scanner.py       # filesystem walk, binary/exclude filtering, matching
│   ├── baseline.py       # save/load/diff accepted-finding fingerprints
│   ├── report.py          # console, JSON, and SARIF report rendering
│   └── cli.py               # argparse entry point
├── rules/
│   └── default_rules.yaml
├── examples/
│   ├── generate_demo.py      # writes examples/vulnerable_repo/ (gitignored, not committed)
│   └── README.md
├── tests/
│   ├── test_entropy.py
│   ├── test_rules.py
│   ├── test_scanner.py
│   ├── test_baseline.py
│   ├── test_report.py
│   └── test_cli.py
├── requirements.txt
└── requirements-dev.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Possible extensions

- Add a `--staged` mode that diffs `git diff --cached` instead of walking
  the working tree, for use as a pre-commit hook.
- Scan git history (not just the working tree) to catch secrets that were
  committed and later removed but still live in old commits.
- Ship a pre-commit-framework hook definition (`.pre-commit-hooks.yaml`).
