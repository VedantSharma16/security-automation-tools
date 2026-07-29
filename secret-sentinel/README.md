# Secret Sentinel

A from-scratch secrets/credential-leak scanner: regex signatures for known
vendor key formats, Shannon-entropy analysis for everything else, git-history
scanning (so a secret that was committed and later "deleted" still gets
caught), an allowlist baseline, and optional LLM-assisted triage of ambiguous
findings.

## Why this exists

Every other project in this repo is about detecting an attack in progress
(logs, alerts, running processes). This one is about the leak that causes
the incident in the first place — a hardcoded AWS key or a `.env` file
committed by accident is one of the most common, most preventable ways
organizations actually get breached, and it's squarely an AppSec/DevSecOps
problem rather than a blue-team-on-a-host one. It's also a natural home for
LLM triage: static rules over-flag ambiguous, high-entropy-looking strings
(UUIDs, hashes, test fixtures), and a model can look at that specific
handful of ambiguous cases and reason about which ones are actually secrets.

## Features

- **Signature matching** — 14 regex signatures for well-known formats (AWS
  access keys & secret keys, GitHub tokens, Slack tokens/webhooks, GCP API
  keys, Stripe live keys, SendGrid, Twilio, PEM private key blocks, JWTs,
  database connection strings with embedded credentials, and generic
  key/token/password-shaped assignments).
- **Entropy-based generic detection** — anything assigned to a
  suspiciously-named variable (`*_token`, `*_secret`, `db_password`, ...)
  that isn't a known vendor format is still flagged if its Shannon entropy
  is high enough to look random rather than typed by a human, with an
  explicit placeholder allowlist (`changeme`, `your-api-key-here`, `example`,
  ...) to keep the obvious non-issues quiet.
- **Git-history scanning** (`--git-history`) — walks every line ever added
  across `git log -p`, so a secret that was committed and rotated out in a
  later commit is still found; working-tree-only scanning can never see it.
- **Allowlist baseline** (`--allowlist` / `--update-allowlist`) — fingerprint
  a finding by its *value*, not its file/line, so an accepted finding (a
  known test fixture, a rotated credential intentionally left in a fixture)
  stays suppressed even if the code around it moves.
- **Optional LLM triage** (`--llm`) — sends only ambiguous (low/medium
  confidence) findings to an LLM for a true/false-positive verdict, grounded
  in the redacted preview + entropy + detector rationale — **never the raw
  secret value** — with a deterministic offline heuristic fallback when no
  `ANTHROPIC_API_KEY` is set.
- **Redaction by construction** — every finding stores only a first-4/last-4
  redacted preview and a short one-way fingerprint; the full secret value is
  never written to the console, the JSON report, or an LLM prompt.
- **Inline suppression** — a trailing `# secret-sentinel:ignore` comment
  silences a specific line (for accepted test fixtures, etc.).
- **Automation-friendly exit codes** for pre-commit hooks / CI (`0` clean,
  `1` findings, `2` error) — see [`examples/pre-commit-hook.sh`](examples/pre-commit-hook.sh).
- 77 pytest tests covering entropy scoring, signature loading/validation,
  the scanner, git-history parsing (against a real throwaway git repo),
  the allowlist, reporting, LLM triage (offline heuristic + response
  parsing), and the CLI end-to-end.

## Installation

```bash
cd secret-sentinel
pip install -e ".[dev]"
```

## Usage

```bash
# Scan the current directory (or a specific path)
secret-sentinel .
secret-sentinel /path/to/repo

# Only high/critical, no color, write a JSON report
secret-sentinel . --min-severity high --no-color --json-out report.json

# Scan the full commit history instead of the working tree
secret-sentinel /path/to/repo --git-history

# ... or just the last 50 commits
secret-sentinel /path/to/repo --git-history 50

# Send ambiguous findings to an LLM for true/false-positive triage
# (falls back to an offline heuristic if ANTHROPIC_API_KEY isn't set)
secret-sentinel . --llm

# Accept the current findings as known/expected, suppress them going forward
secret-sentinel . --allowlist allowlist.json --update-allowlist
secret-sentinel . --allowlist allowlist.json   # quiet on anything in the allowlist

# Try it against the bundled example
secret-sentinel examples/vulnerable_snippet.py
```

Exit codes: `0` = no findings (after `--min-severity` filtering), `1` =
findings reported, `2` = a fatal error (missing rules file, target isn't a
git repo for `--git-history`, ...).

To silence one specific line without an allowlist entry:

```python
DEMO_KEY = "not-a-real-secret-but-looks-like-one"  # secret-sentinel:ignore
```

## How detection works

1. **Named signatures** (`rules/default_patterns.yaml`) run first. These are
   high-confidence, low-noise regexes for specific vendor formats — an AWS
   key ID always starts with `AKIA` + 16 uppercase-alnum characters, so
   false positives are rare by construction.
2. For anything not already caught, the **generic entropy detector**
   (`secret_sentinel/entropy.py`) looks for `<secret-shaped-name> = "<value>"`
   assignments (matching on the variable name containing `key`, `secret`,
   `token`, `password`, `auth`, etc. as a substring — deliberately not
   anchored to the start of the identifier, since `db_password` and
   `stripe_secret_key` are exactly the shapes real code uses) and computes
   the [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
   of the value in bits/character. A short, low-entropy, or obviously-placeholder
   value is left alone; a long, high-entropy one is flagged as
   `generic-high-entropy-string` at **low confidence**.
3. Low/medium-confidence findings are the ones worth a second opinion —
   that's what `--llm` is for. High-confidence named signatures don't need
   one.

### Known trade-offs

- Variable-name matching is substring-based (`monkey_name` "matches" because
  it contains `key`), which trades some precision for not missing
  `db_password`-style naming. The entropy check is what keeps this usable in
  practice — false-positive names rarely also hold a high-entropy value.
- Entropy scoring can't distinguish "random and secret" from "random and not
  secret" (a UUID or password hash looks identical to a real API key by this
  measure alone) — that's precisely the gap `--llm` triage is designed to
  narrow, not eliminate.
- Fingerprints are `sha256(signature_id:value)[:16]` — a convenience hash for
  allowlisting/deduplication, not a security boundary. Don't treat a
  fingerprint as safe to publish in place of the secret.

## Project layout

```
secret-sentinel/
├── secret_sentinel/
│   ├── patterns.py      # YAML signature loading + validation
│   ├── entropy.py       # Shannon entropy + generic secret-shaped detection
│   ├── scanner.py       # filesystem walk, per-line detection, redaction
│   ├── gitscan.py        # git log -p parsing for history scanning
│   ├── baseline.py      # allowlist fingerprint save/load/filter
│   ├── report.py         # console + JSON reporting, risk scoring
│   ├── llm_triage.py     # LLM-assisted triage + offline heuristic fallback
│   └── cli.py             # argparse entry point
├── rules/
│   └── default_patterns.yaml
├── examples/
│   ├── vulnerable_snippet.py
│   └── pre-commit-hook.sh
├── tests/
│   ├── fixtures/sample_repo/   # files with fake secrets used by test_scanner.py
│   └── test_*.py
└── pyproject.toml
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Possible extensions

- Ship additional signatures (Azure, Kubernetes secrets, npm/PyPI tokens).
- Parallelize git-history scanning for large repos instead of one `git log -p` pass.
- A GitHub Action wrapper that comments on a PR diff instead of failing the whole build.
