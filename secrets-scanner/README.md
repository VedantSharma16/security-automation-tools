# secretscanner

A command-line secret scanner that checks both a repository's **working
tree** and its full **git commit history** for leaked credentials —
AWS/GitHub/Stripe/Slack/Google/Twilio/NPM tokens, private key blocks, JWTs,
and generic high-entropy strings — then triages findings to separate likely
genuine leaks from noise, with an optional LLM-written analyst narrative.

Scanning history matters: a credential that was committed and later
"removed" in a follow-up commit is still fully recoverable with
`git log -p` or `git show`. Working-tree-only scanners miss this entirely;
`secretscanner --history` re-runs detection against every commit's diff so
that class of leak doesn't slip through.

## Why history-aware, and why triage matters

Every real secret-scanning tool (gitleaks, trufflehog, detect-secrets)
supports history scanning for the reason above, and every one of them gets
noisy without false-positive triage — a report that's mostly test fixtures
and `your_api_key_here` placeholders trains developers to ignore it. This
tool applies deterministic, explainable heuristics (file path looks like a
test/fixture; value looks like a placeholder; low-severity entropy-only
match with no known credential format) *before* anything reaches an LLM, so
the optional narrative step stays cheap, fast, and grounded in the same
signal a human reviewer would use — the same "detectors stay deterministic,
LLM only writes prose on top of evidence" pattern used throughout this repo.

## What it detects

**Format-specific (high confidence):** AWS access keys & secret keys,
GitHub PATs, Slack tokens & webhooks, Stripe secret keys, Google API keys,
Twilio API keys, NPM tokens, PEM private key blocks, JWTs, and a generic
`key/secret/token/password = "..."` assignment pattern.

**Shannon-entropy fallback (lower confidence):** any other long hex- or
base64-like token whose per-character entropy sits near the ceiling for its
alphabet — catches one-off credentials with no fixed format.

Inline suppression is supported via a trailing `# pragma: allowlist secret`
or `# secretscanner: ignore` comment, matching the convention used by
detect-secrets/gitleaks.

## Install

```bash
cd secrets-scanner
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
secretscanner path/to/project                              # working tree only
secretscanner path/to/repo --history                       # + full git history
secretscanner path/to/repo --history-only                  # history only, skip working tree
secretscanner path/to/repo --history --max-commits 200      # cap history depth for large repos
secretscanner path/to/project --min-severity high           # only critical/high findings
secretscanner path/to/project --format json --out report.json
secretscanner path/to/project --llm                          # Claude-written analyst narrative
```

Exit code is `2` if any finding survives triage as "likely genuine" (useful
as a CI gate), `1` on a usage/path error, `0` if the scan is clean.

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic offline narrative — it's always usable with no API key or
network access, and that's what the test suite runs against.

Try it against the included example (deliberately-leaky, all fake values):

```bash
secretscanner examples/vulnerable_sample
```

## Architecture

```
secretscanner/
  patterns.py    vendor-specific regex signatures + severity/remediation metadata
  entropy.py     Shannon-entropy scoring for generic, format-less secrets
  scanner.py     walks a directory / scans text -> list[Finding]
  gitscan.py     parses `git log -p` diffs -> Finding list, one per commit that introduced a secret
  triage.py      rule-based false-positive heuristics + LLM/offline narrative (SecretTriageClient)
  report.py      findings + narrative -> structured report dict, JSON/Markdown rendering
  cli.py         argparse entry point wiring the above together
```

Each stage consumes only the previous stage's output, so it's independently
unit-testable — see `tests/`, which covers every pattern against a matching
sample and a benign-code negative set, entropy edge cases, suppression
comments, a real temporary git repo with a secret committed-then-removed,
triage heuristics, report rendering, and the CLI end-to-end.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## Limitations

This is a portfolio/educational project, not a production secrets-management
control. Entropy detection has an inherent false-positive/false-negative
tradeoff (tune `HEX_ENTROPY_THRESHOLD` / `BASE64_ENTROPY_THRESHOLD` in
`entropy.py` for your codebase); the generic-assignment regex will miss
secrets that don't sit next to a recognizable keyword; and history scanning
reads the full `git log -p` output, so very large repositories should use
`--max-commits` to bound run time. Only scan repositories you own or are
authorized to assess.
