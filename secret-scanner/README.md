# Secret Scanner

A static secret-detection tool: it scans a working tree (or the *entire git
history* of a repository) for hardcoded credentials — cloud keys, VCS
tokens, private keys, connection strings — and reports them with severity,
location, and a stable fingerprint for triage. It ships with a
baseline/allowlist workflow and SARIF output so it can gate a CI pipeline
the same way commercial tools like gitleaks or truffleHog do.

## Why this exists

Leaked credentials are consistently one of the top initial-access vectors in
real breaches, and "we deleted the secret in a later commit" doesn't help —
it's still sitting in `git log`. This project is a from-scratch
demonstration of that specific detection problem: pattern + entropy-based
detection, full-history scanning (not just the current checkout), and a
review workflow (baseline) that keeps a scanner usable in a real repo
instead of crying wolf on every run. It's the AppSec/DevSecOps complement to
the runtime-focused tools elsewhere in this repo (`process_threat_hunter`,
`recon-agent`, `log-triage-assistant`).

## Features

- **12 targeted detectors** for AWS keys, GitHub tokens (classic + fine-grained),
  Slack tokens/webhooks, Google API keys, Stripe keys, npm tokens, JWTs, PEM
  private key blocks, and credentials embedded in connection-string URLs.
- **Generic high-entropy fallback** — flags `secret_like_name = <high-entropy
  value>` assignments that don't match any known vendor format, using
  Shannon entropy normalized against the value's likely alphabet (hex /
  base64 / ASCII) so it doesn't fire on natural-language strings or padding
  like `"aaaaaaaa"`.
- **Full git history scanning** (`secret-scanner history`) — parses `git log
  -p` across every commit and reachable ref, so a secret that was committed
  and later "fixed" is still caught. A companion working-tree scan
  (`secret-scanner scan`) covers files as they exist on disk right now.
- **Baseline / allowlist workflow** — `--create-baseline` records the
  fingerprint of every current finding; `--baseline` suppresses anything
  already recorded on future runs, so accepted false positives (test
  fixtures, rotated keys, docs examples) don't re-alert forever. Fingerprints
  are keyed on rule + file + secret value, so they survive line-number
  drift.
- **Three output formats**: human-readable text, JSON, and
  [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for upload to GitHub
  Code Scanning / any SARIF-consuming tool.
- **CI-friendly exit codes** — non-zero when findings meet or exceed
  `--fail-on` (default: `medium`), so it can gate a pipeline; `--fail-on
  none` for report-only runs.
- Secrets are **redacted everywhere** in output (first/last 4 characters
  shown, the rest masked) — the tool never prints a usable credential.
- 65 tests (pytest), including integration tests that spin up real temporary
  git repositories to exercise history scanning end-to-end. Stdlib-only, no
  third-party dependencies.

## Installation

```bash
cd secret-scanner
pip install -e .
```

## Usage

```bash
# Scan the current working tree
secret-scanner scan .

# Scan a specific path, writing a SARIF report for GitHub code scanning
secret-scanner scan . --format sarif -o secret-scan.sarif

# Scan the ENTIRE git history, including commits that were later "fixed"
secret-scanner history .

# Only fail CI on critical/high findings
secret-scanner scan . --fail-on high

# Accept the current findings as reviewed/safe, then suppress them going forward
secret-scanner scan . --create-baseline .secret-scanner-baseline.json
secret-scanner scan . --baseline .secret-scanner-baseline.json

# Skip an additional vendored directory
secret-scanner scan . --exclude-dir third_party
```

If a `.secret-scanner-baseline.json` file exists in the current directory
and `--baseline` isn't passed explicitly, it's picked up automatically.

Exit codes: `0` = clean (or all findings below `--fail-on`), `1` = findings
at or above the threshold, `2` = argument error.

## Project layout

```
secret-scanner/
├── secret_scanner/
│   ├── entropy.py     # Shannon entropy + high-entropy assignment detection
│   ├── detectors.py    # regex rules + generic entropy fallback -> RawMatch
│   ├── scanner.py        # file-tree walking, git-history diff parsing -> Finding
│   ├── baseline.py         # fingerprint allowlist: save/load/filter
│   ├── report.py             # text / JSON / SARIF rendering
│   └── cli.py                   # argparse entry point (scan / history)
├── tests/
│   ├── secret_fixtures.py            # fake, format-valid secrets, split apart in source
│   ├── fixtures/clean_file.py     # a file with nothing sensitive in it
│   ├── test_entropy.py
│   ├── test_detectors.py
│   ├── test_scanner.py
│   ├── test_baseline.py
│   ├── test_report.py
│   └── test_cli.py
└── pyproject.toml
```

## How git-history scanning works

`secret-scanner history` runs `git log --all --unified=0 -p` once and parses
the combined diff output as a small state machine: it tracks the current
commit (hash/author/date via a custom `--format`), the current file (from
`diff --git a/... b/...` headers), and the new-file line counter (from `@@
-a,b +c,d @@` hunk headers), then feeds every added (`+`) line through the
same detectors used for working-tree scanning. This is what catches a
secret that was committed once and removed in a later commit — a plain
file-tree scan can never see that, because on disk it's already gone.

## A note on the test fixtures

The test fixtures need realistic, format-valid fake secrets to exercise the
detectors properly - but a *contiguous* fake AWS key or Slack token sitting
in a public repo is exactly what GitHub's own push protection (correctly)
blocks. `tests/secret_fixtures.py` builds each fake value from split string
literals at runtime, so the committed source never contains a contiguous
match, while the actual test process still sees the full value it needs.

## Limitations / possible extensions

- Detectors are regex/entropy based; a sufficiently obfuscated or
  low-entropy secret (e.g. a short shared password) can slip through.
  Tune `find_high_entropy_assignments`'s thresholds for your codebase.
- `history` re-scans the full log every run; for a very large, long-lived
  repo, `--max-commits` limits the window, and a future version could cache
  per-commit results keyed on commit hash.
- No native pre-commit hook yet — `secret-scanner scan --fail-on high` can
  be wired into `.pre-commit-config.yaml` or a CI step directly today.

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```
