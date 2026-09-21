# secretscan

A git-aware secrets/credential leak scanner: it checks both the current
working tree *and* full git history (every commit, all branches) for
hardcoded credentials, filters noise with Shannon-entropy analysis, and
speaks SARIF so it plugs straight into GitHub code scanning or any CI
pipeline.

## Why this exists

The other tools in this repo triage things that already happened (log
events, alerts, process activity) or scope out what an attacker could
reach (`recon-agent`). `secretscan` is the other half of AppSec/DevSecOps
work: preventing the leak in the first place, and catching the ones that
already happened and are still sitting in history.

A secret that only ever lived in the working tree disappears the moment
someone deletes it. A secret that was ever **committed** lives forever in
git history — every clone of the repo has it — unless the history itself is
rewritten. Most "secret scanner" toy projects only grep the checked-out
files, which misses exactly the scenario that matters most in practice:
*"we found the key in `config.py` and deleted it three months ago — are we
actually safe?"* `secretscan --include-history` answers that question by
walking every commit's diff, not just `HEAD`.

```
$ secretscan .                        # working tree only: clean
No secrets found. \o/

$ secretscan . --include-history      # the key is still in history
[CRITICAL] aws-access-key-id  (high confidence)
  secrets.py:1  @ 723293cacbed
  value    : AKIA...TUVW
  ...
```

## How it works

```
                     ┌─ file scan ───────────┐
target dir ──────────┤                       ├──▶ rule engine (regex + entropy) ──▶ findings
                     └─ git history (--include-history, `git log -p`, all refs) ─┘
                                                          │
                                             baseline allowlist (fingerprint hash)
                                                          │
                                        optional LLM/heuristic triage (generic-secret only)
                                                          │
                                     console / JSON / SARIF report, redacted throughout
```

- **Rule engine** (`rules.py`, `rules/default_rules.yaml`) — 17 rules: 15
  high-confidence signature patterns for specific providers (AWS, GitHub,
  GitLab, Slack, Stripe, Google, SendGrid, Twilio, npm, PEM private keys,
  JWTs, URLs with embedded credentials) plus one deliberately broad
  `generic-secret-assignment` rule that matches *any* `key = "value"` line
  where the variable name sounds secret-related.
- **Entropy filtering** (`entropy.py`) — the generic rule (and the
  credentials-in-a-URL rule) would otherwise flag every
  `api_key = "changeme"` in every codebase. A regex hit only becomes a
  finding if the captured value also has high Shannon entropy *and* doesn't
  match a placeholder heuristic (`changeme`, `xxxxxxxx`, `your_key_here`,
  short runs of repeated characters, ...).
- **Git history scanner** (`gitscan.py`) — shells out to `git log --all -p
  --unified=0` and parses the unified diff itself (no third-party git
  library) to yield every line ever *added* across every branch/tag, with
  its commit, author, and date. Only added lines are scanned — a secret
  that was only ever *removed* isn't a leak this repo's history introduced.
- **Redaction, everywhere** (`redact.py`, `finding.py`) — a `Finding` never
  carries the raw secret past the moment it's matched. Only a
  `first4...last4` preview and a SHA-256 fingerprint (used for baselining)
  survive into any report. A secrets scanner that prints the secrets it
  finds into a CI log defeats its own purpose.
- **Baseline/allowlist** (`baseline.py`) — `--create-baseline` snapshots the
  fingerprints of today's findings (test fixtures, intentionally-committed
  example keys, rotated credentials kept in history on purpose); future
  scans only fail on *new* findings, the standard gitleaks/trufflehog
  workflow.
- **Optional LLM triage** (`llm_triage.py`) — the generic entropy rule is
  the one category genuinely ambiguous between "leaked credential" and
  "UUID/hash/test fixture." `--llm-triage` asks Claude to break the tie;
  without an API key it falls back to a small offline keyword heuristic
  (`secret`/`token`/`password` → likely real, `id`/`hash`/`uuid` → likely
  not). **Only the redacted preview and the variable name are ever sent to
  the model — never the raw secret.** Signature-rule findings never need
  triage; the pattern itself is already high-confidence.
- **Reporting** (`report.py`) — console (colorized), JSON, and SARIF 2.1.0.
  SARIF is what turns this from a CLI toy into something a CI pipeline can
  actually gate on — GitHub's `github/codeql-action/upload-sarif` ingests it
  directly into the repo's Security tab.

## Installation

```bash
cd secrets-scanner
pip install -e .          # PyYAML only
pip install -e ".[llm]"   # optional: adds LLM-driven triage of ambiguous findings
```

## Usage

```bash
# Scan the working tree
secretscan .

# Also walk full git history (all branches/tags) -- the important case
secretscan . --include-history

# Only report high+ severity, write SARIF for CI upload
secretscan . --include-history --min-severity high --sarif-out results.sarif

# Seed a baseline from today's findings, then only fail on *new* ones
secretscan . --include-history --baseline .secretscan-baseline.json --create-baseline
secretscan . --include-history --baseline .secretscan-baseline.json

# Use Claude to triage the ambiguous generic-entropy findings (needs ANTHROPIC_API_KEY)
secretscan . --llm-triage

# Try it on the bundled example (well-known public placeholder keys only)
secretscan examples/
```

Exit codes (so it slots into a pre-commit hook or a CI job): `0` clean,
`1` findings at/above `--min-severity`, `2` error (bad path, bad rule file,
not a git repo when `--include-history` was requested).

### GitHub Actions

```yaml
- name: Secret scan
  run: |
    pip install -e ./secrets-scanner
    secretscan . --include-history --sarif-out results.sarif
  continue-on-error: true   # let the SARIF upload annotate the PR instead of hard-failing
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Design decisions worth calling out

- **Shells out to `git` instead of a library dependency.** Keeps the tool
  dependency-free for the file-scan path and matches the "stdlib-first"
  approach used elsewhere in this repo. The cost is two documented parsing
  edge cases: merge commits (`git log -p` shows no diff for them by
  default) and filenames containing spaces (the diff-header regex takes the
  simple case). Neither affects the overwhelming majority of real repos.
- **Redact before it ever reaches a report, a baseline file, or an LLM
  prompt.** A `Finding`'s raw matched text exists only inside `rules.py`'s
  `find_all()` and the constructor call right after it — nothing downstream
  ever sees it again.
- **Fingerprints exclude the line number on purpose** — an unrelated edit
  that shifts a baselined finding a few lines up or down shouldn't un-suppress
  it, but a genuinely different secret value should always get a new
  fingerprint even on the same line.
- **The generic rule is intentionally noisy, and that's the point.**
  Signature rules can't catch a company's own internal token format. The
  entropy + placeholder filter (not the regex) is what keeps that rule
  usable instead of flagging every config value in a repo; `--llm-triage`
  (or its offline fallback) then ranks the survivors by confidence instead
  of presenting them as a flat, equally-weighted list.

## Known limitations

- Regex + entropy will never catch a secret that doesn't *look* random
  (e.g. a weak, dictionary-word password) — that's a different problem
  (credential-strength policy), not what this tool targets.
- `--include-history` walks every commit on every ref with `git log --all
  -p`; on a very large, very old repository that can take a while. There's
  no incremental/since-last-scan mode yet.
- Binary diffs and merge-commit diffs are skipped (git itself doesn't show
  a line-level diff for either without extra flags this tool doesn't pass).

## Testing

```bash
pip install -e ".[dev]"
pytest
```

72 tests, all offline (git-history tests spin up real throwaway repos under
pytest's `tmp_path`; LLM-triage tests fake the `anthropic` module so no
network access or API key is required).
