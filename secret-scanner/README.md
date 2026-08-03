# secretscan

A git-aware scanner for hardcoded secrets and credential leaks — regex
detectors for known secret formats (AWS, GitHub, Slack, Stripe, private
keys, JWTs, ...), a Shannon-entropy heuristic for everything else, and a
git-history mode that catches secrets that were committed and later
"removed" (rotating the credential, not the file, is the actual fix — the
leak is still in every clone's `.git` history). Exit codes and JSON output
are designed to slot straight into CI as a merge-blocking security gate.

## Why this exists

Committing a credential to source control is one of the most common real
incident triggers in application security — it's fast, avoidable, and
recruiters/hiring managers in AppSec and IR roles recognize a working
gitleaks/truffleHog-style tool on sight. This project is a from-scratch
implementation of that category, distinct from this repo's other alert/log
triage tools: it's a static analysis tool aimed at *preventing* an incident
rather than *responding* to one, and it's built to run as a CI gate, a
pre-commit check, or a one-off repo audit.

## Features

- **19 regex rules** for known secret formats: AWS access/secret keys, GCP
  API keys and service-account JSON, GitHub/GitLab tokens, Slack tokens
  and webhooks, Stripe/SendGrid/Twilio/npm/OpenAI/Anthropic keys, PEM
  private key blocks, JWTs, basic-auth URLs (e.g. leaked DB connection
  strings), and generic API-key/password assignments.
- **Shannon-entropy heuristic** (`secretscan/entropy.py`) for secrets in a
  company's own internal format that no public rule set enumerates: an
  assignment to a security-sounding variable name whose value is long,
  high-entropy, *and* mixes at least two character classes (digits/upper/
  lower/symbol) — that last check specifically rules out plain
  natural-language phrases like `correcthorsebatterystaple`, which score
  surprisingly high on raw entropy alone despite being one character class.
- **Git-history scanning** (`--git-history`) — walks every commit's added
  lines (via `git log -p --unified=0`, parsed for accurate per-commit line
  numbers) across all branches by default, so a secret that was committed
  and later deleted still gets flagged, tagged with the commit it was
  introduced in.
- **Redaction by design** — only the matched secret value is ever recorded
  in a finding (e.g. `AKIA****EXAMPLE` → `AKIA********MPLE`), never the raw
  value; full-length values are never written to a report, console, or the
  LLM prompt.
- **`.secretsallowlist`** — a dependency-free plain-text allowlist (path
  globs, rule IDs, regexes, or exact literals) for suppressing confirmed
  false positives, plus a small built-in list of common placeholder values
  (`changeme`, `hunter2`, ...) that are always suppressed.
- **Severity-weighted risk score** (0–100) and a structured JSON report,
  alongside a readable, severity-colored console report.
- **CI-friendly exit codes** — `0` clean, `1` findings (after
  `--min-severity` filtering), `2` a fatal error — and `--min-severity` to
  gate only on what matters (e.g. `high` and above) while still recording
  lower-severity findings in the JSON report.
- **Optional LLM executive summary** (`--llm`) — same pattern as this
  repo's other tools: a deterministic offline template summarizer by
  default, and an opt-in Claude-generated summary that is only ever given
  the already-redacted structured findings, never raw file contents.
- 100 pytest tests, including a real temporary git repository fixture for
  the history scanner (not mocked) and end-to-end CLI tests.

## Installation

```bash
cd secret-scanner
pip install -e .
# or, for the optional LLM summary:
pip install -e ".[llm]"
```

## Usage

```bash
# Scan the working tree of the current directory
secretscan .

# Also scan every commit's added lines across all branches
secretscan . --git-history

# Only fail (and report) on high/critical findings -- good for a CI gate
secretscan . --min-severity high

# Machine-readable output for tooling
secretscan . --format json --json-out report.json

# Suppress known false positives (see examples/vulnerable-repo/.secretsallowlist)
secretscan . --allowlist .secretsallowlist

# Generate the executive summary with Claude instead of the offline template
ANTHROPIC_API_KEY=sk-ant-... secretscan . --llm
```

Exit codes: `0` = no findings (after `--min-severity` filtering), `1` =
findings reported, `2` = a fatal error (e.g. not a directory, or
`--git-history` on a path that isn't a git repository).

### Try it on the bundled demo repo

`examples/vulnerable-repo/` contains a handful of intentionally-fake
secrets (AWS's own published `EXAMPLE` test key, obviously-fake tokens,
etc.) covering most of the rule set, plus a `.secretsallowlist` that
suppresses a JWT fixture used in its own tests:

```bash
secretscan examples/vulnerable-repo --allowlist examples/vulnerable-repo/.secretsallowlist
```

## Rule format

Rules are plain Python data in `secretscan/rules.py` rather than an
external YAML file — unlike host-signature rules, a secret format's shape
is effectively fixed (an AWS access key ID has one shape), so there's
little value in a runtime-editable rule file for the built-in set. Each
rule is:

```python
_rule(
    "github-pat",
    r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
    "critical",
    "GitHub personal access / OAuth / app / refresh token.",
)
```

A rule that needs to anchor on a variable name (e.g. `aws-secret-access-key`,
which matches `aws_secret_access_key = "..."` rather than a
self-describing value) sets `value_group` to the index of the capture
group holding the actual secret, so only that value — never the
surrounding variable name — is redacted and reported.

## `.secretsallowlist` format

```
# comment
path:tests/fixtures/**
rule:jwt
regex:^AKIAFAKEEXAMPLE
literal:hunter2
```

## Project layout

```
secret-scanner/
├── secretscan/
│   ├── rules.py         # regex rule definitions + redaction
│   ├── entropy.py        # Shannon-entropy generic-secret heuristic
│   ├── allowlist.py       # .secretsallowlist parsing + suppression
│   ├── scanner.py          # working-tree file walk + line scanning
│   ├── git_history.py       # git log -p diff parsing + history scanning
│   ├── report.py              # risk scoring, console/JSON rendering
│   ├── llm_summary.py          # offline + optional Claude executive summary
│   └── cli.py                    # argparse entry point
├── examples/vulnerable-repo/       # demo repo with fake secrets + an allowlist
├── tests/
└── pyproject.toml
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Known limitations

- The entropy heuristic is a blunt instrument by nature: it will still
  miss deliberately low-entropy secrets and can flag high-entropy
  non-secrets (UUIDs, content hashes, minified build IDs). It's designed
  to be a lower-confidence, `low`-severity signal, and is fully
  suppressible via `--no-entropy` or the allowlist.
- Git-history line numbers are derived from each commit's diff hunk
  headers, not a full blame — accurate for the commit's state at the time,
  but a line added mid-hunk in a diff whose content itself starts with
  `++ ` could in principle be misparsed as a file header. This is a
  known, narrow edge case of parsing unified diffs as text.
- This is a detection tool, not a prevention tool: it doesn't rewrite git
  history or rotate credentials. Treat every flagged secret as burned —
  rotate it at the provider — regardless of whether history is scrubbed.

## Possible extensions

- A `pre-commit` hook wrapper so leaks are caught before a push, not after.
- Verify findings live against provider APIs (e.g. check whether a flagged
  AWS key is still active) to separate "leaked and live" from "leaked and
  already rotated."
- Parallelize the working-tree walk for large monorepos.
