# secret-scanner

A git-aware credential leak scanner: known-provider signatures, Shannon-entropy
detection for unknown formats, and full **git history** scanning -- so a
secret that was committed and later "removed" still gets caught, because it's
still sitting in a reachable git object.

## Why this exists

Hardcoded credentials in source control are one of the most common, highest-
impact findings in real assessments and real incidents -- and a huge fraction
of "we removed the key" incidents are actually "we removed the key from
`HEAD`," which does nothing, because `git log -p` (or a clone) still has it.
This tool demonstrates that detection model end to end: multi-format
signature matching, entropy-based fallback detection, false-positive
suppression, and history-aware scanning that a pure filesystem grep can't do
-- packaged as something that can gate a commit or a CI pipeline, not just
print a report.

## Features

- **20+ provider signatures** -- AWS access keys & secret keys, GitHub
  (classic + fine-grained) tokens, Slack tokens/webhooks, Stripe, Google API
  keys, Twilio, SendGrid, npm tokens, PEM private key blocks, JWTs, database
  connection strings with embedded credentials, and generic
  `api_key`/`password`/`token` assignments.
- **Shannon-entropy fallback** for secrets in no recognized format: flags
  long, high-entropy base64/hex-like tokens, with separate thresholds for
  hex vs. base64 alphabets and a low-character-variety filter to reject
  merely-long-but-not-random strings.
- **Full git history scanning** (`--git-history`) -- walks every commit's
  *added* lines via `git show --unified=0` (no full checkout per commit,
  no GitPython dependency) so it also catches secrets that only ever
  existed in a deleted line of an old commit.
- **False-positive suppression** -- default-ignored directories/extensions
  (`node_modules`, `vendor`, binaries, ...), placeholder-value detection
  (`AKIAIOSFODNN7EXAMPLE`, `changeme`, repeated-character strings, ...),
  inline `# secret-scanner:ignore` suppression, and a `.secretscanignore`
  file for path globs / value regexes specific to a repo.
- **Redaction by construction** -- `Finding` objects never carry the raw
  secret value, only a masked form (`AKIA****MNOP`); reports, console
  output, and any LLM triage call all only ever see the redacted form.
- **Console, JSON, and Markdown reports**, with a risk score and
  severity breakdown -- the Markdown output is meant to be pasted straight
  into a PR comment or CI summary.
- **Automation-friendly exit codes** (`0` clean / `1` findings / `2` error),
  a working `examples/pre-commit` git hook, and a `--min-severity` gate --
  built to run as a commit hook or a CI step, not just interactively.
- **Optional LLM-assisted triage narrative** (`--llm`, uses Claude): grounded
  strictly in the redacted, structured findings -- the model never sees an
  actual secret value, only its type/location/entropy. Falls back to a
  deterministic offline template summarizer (the default, and what tests run
  against) when no API key is configured.
- 92 tests, no real network calls, no static "real-looking" secrets checked
  into the repo -- test fixtures assemble fake, provider-format-matching
  values from string fragments at runtime instead of literal contiguous
  strings (see `tests/secret_fixtures.py`), and the project's own
  `.secretscanignore` demonstrates suppressing its own necessarily
  secret-shaped test fixtures. Running `secret-scanner` on this repository
  itself reports clean.

## Installation

```bash
cd secret-scanner
pip install -r requirements.txt   # stdlib-only; nothing to install for the core scanner
pip install -e ".[llm]"           # optional, only needed for --llm
```

## Usage

```bash
# Scan the working tree of a repo
python -m secret_scanner.cli /path/to/repo

# Also scan full git history (catches secrets removed from HEAD but still in old commits)
python -m secret_scanner.cli /path/to/repo --git-history

# Only scan history back to a ref (e.g. the last release), for a fast CI check on a PR
python -m secret_scanner.cli /path/to/repo --git-history --since v1.4.0

# Gate on severity, write reports for CI artifacts / PR comments
python -m secret_scanner.cli /path/to/repo --min-severity high \
    --json-out report.json --markdown-out report.md

# Signature-only (skip entropy scanning) for a lower-noise, high-confidence pass
python -m secret_scanner.cli /path/to/repo --no-entropy

# LLM-assisted triage narrative (requires ANTHROPIC_API_KEY; falls back to the
# offline template summarizer if it's not set or the anthropic package isn't installed)
python -m secret_scanner.cli /path/to/repo --llm
```

Exit codes: `0` = no findings (after `--min-severity` filtering), `1` =
findings reported, `2` = a fatal error (e.g. path doesn't exist).

### Suppressing false positives

```
# .secretscanignore, at the root of the repo being scanned
path:tests/fixtures/*
path:*.md
value:^TEST-.*
```

or inline, on the offending line itself:

```python
DEMO_KEY = "AKIAIOSFODNN7EXAMPLE"  # secret-scanner:ignore
```

### Wiring into git / CI

```bash
cp examples/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

```yaml
# .github/workflows/secret-scan.yml
- name: Scan for hardcoded secrets
  run: |
    python -m secret_scanner.cli . --git-history --min-severity high \
      --json-out secret-scan-report.json --no-narrative
```

## Project layout

```
secret-scanner/
├── secret_scanner/
│   ├── signatures.py     # regex signatures for known credential formats
│   ├── entropy.py        # Shannon-entropy fallback detection
│   ├── allowlist.py       # path/value suppression, .secretscanignore parsing
│   ├── findings.py         # Finding record, redaction, dedup, risk scoring
│   ├── scanner.py           # working-tree file scanning
│   ├── git_history.py        # per-commit added-line scanning via `git show`
│   ├── report.py               # console / JSON / Markdown report rendering
│   ├── llm_triage.py             # offline template + optional Claude narrative
│   └── cli.py                     # argparse entry point
├── examples/
│   └── pre-commit                  # sample git hook
├── tests/
│   ├── secret_fixtures.py           # synthetic, format-matching fake secrets
│   └── test_*.py
├── .secretscanignore
├── pyproject.toml
└── requirements.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Design notes / limitations

- Signature-based detection is inherently a moving target -- provider token
  formats change, and this rule set (~15 signatures) is illustrative, not
  exhaustive. It's structured so adding a new `Signature` to
  `signatures.py` is a one-line addition, and it's the same trade-off every
  production secret scanner makes: precision from known formats, recall
  from entropy.
- Entropy detection is deliberately conservative (default base64 threshold
  4.3 bits/char, 20-char minimum, low-variety filter) to keep console output
  usable; tune `--entropy-threshold` down for a more paranoid pass.
- Git history scanning only inspects *added* lines per commit, which is
  what actually matters for "is this secret reachable from a clone" --
  but a very large, very old repository's full history can still take a
  while; `--since`/`--max-commits` bound the work for CI.
- This tool finds where a secret *is*; it does not verify whether it's
  still live. Treat every finding as "rotate this credential," not
  "confirm this credential still works" (verifying would mean calling out
  to the provider with the secret itself, which this tool deliberately
  never does).

## Possible extensions

- Ship a pre-built GitHub Action / Docker image for one-line CI adoption.
- Add provider-side revocation-API verification (opt-in, since it requires
  transmitting the secret itself to the provider) to separate "shaped like
  a key" from "confirmed live credential."
- Parallelize git history scanning across commits for very large repos.
