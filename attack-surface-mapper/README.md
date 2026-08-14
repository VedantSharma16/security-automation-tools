# Attack Surface Mapper

Passive/light-touch web reconnaissance and attack-surface triage for
**authorized** security assessments — pentest engagements, bug bounty
programs, or your own blue-team exposure reviews. It fetches a target once,
runs a small set of non-destructive analysis modules against that response
(and, optionally, a curated exposure-path probe), scores the findings, and
produces a prioritized report.

> **Authorization required.** This tool makes live HTTP requests to the
> target you point it at. Only run it against systems you own or have
> explicit written permission to test. `--enable-exposure-checks` performs
> extra requests beyond the initial fetch and is opt-in for that reason.

## Why this exists

Attack-surface enumeration is the first step on both sides of the fence:
red-teamers use it to scope an engagement, blue-teamers use the same
checks to know what an external attacker sees before they do. This project
also demonstrates a different LLM integration pattern than the other tools
in this repo: instead of RAG retrieval, the "agentic" planner here is a
genuine **Claude tool-use loop** — the model is handed a toolbox and
decides for itself which checks to run, in what order, and when it has
enough information to stop, rather than following a fixed pipeline.

## Features

- **Security header audit** — CSP, HSTS, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy, cookie
  Secure/HttpOnly/SameSite flags, and Server/X-Powered-By version
  disclosure.
- **robots.txt / sitemap.xml recon** — both are self-disclosed maps of
  paths the site owner cares about; flags disallowed paths that look
  sensitive (`admin`, `.git`, `backup`, `.env`, ...).
- **Technology fingerprinting** — signature-based detection (headers +
  body) of CMSes, web servers, frameworks, and CDNs/WAFs, from a local,
  editable `data/signatures.json`.
- **Opt-in exposure-path probe** — a curated list of commonly
  misconfigured sensitive paths (`.env`, `.git/config`, backup files,
  cloud credential files, `server-status`, Spring Actuator, ...) in
  `data/exposure_paths.json`, only run with `--enable-exposure-checks`.
- **Agentic planner** — with `ANTHROPIC_API_KEY` set, a Claude tool-use
  loop decides which of the above modules to run and in what order, then
  writes a short assessment and a recommended next step. Without a key
  (or with `--offline`), a deterministic planner runs every available
  module in a fixed, sensible order — same report shape either way, so
  the CLI (and the whole test suite) works fully offline.
- **Risk scoring** — findings are weighted by severity into a 0-100 score
  and a `clean` → `critical` rating; the CLI exits non-zero on
  `high`/`critical`, so it can gate a CI job.
- **JSON + Markdown + console reports**, with severity-colored console
  output and a `--min-severity` filter.
- Zero required runtime dependencies (stdlib `urllib` only); `anthropic`
  is an optional extra for the agentic planner. 56 unit tests, all
  running against mocked HTTP responses and a fake Anthropic client — no
  real network or API calls in the test suite.

## Installation

```bash
cd attack-surface-mapper
pip install -e ".[llm,dev]"   # or just ".[dev]" to skip the agentic planner
```

## Usage

```bash
# Deterministic offline scan (no API key needed)
python -m asmapper.cli https://example.com --offline

# Agentic scan (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-...
python -m asmapper.cli https://example.com

# Also probe common exposure paths (.env, .git/config, backups, ...) — opt-in
python -m asmapper.cli https://example.com --enable-exposure-checks

# Only show medium+ findings in the console, write full JSON + Markdown reports
python -m asmapper.cli https://example.com --min-severity medium \
    --json-out report.json --md-out report.md
```

Exit codes: `0` if the rating is `clean`/`low`/`medium`, `1` if
`high`/`critical` — so it can gate a CI job on newly-introduced exposure.

See [`examples/sample_report.md`](examples/sample_report.md) for a sample
Markdown report from an offline run against a synthetic target.

## Project layout

```
attack-surface-mapper/
├── asmapper/
│   ├── fetcher.py           # stdlib-only HTTP GET client, never raises
│   ├── models.py             # Severity enum + Finding record
│   ├── headers_audit.py       # security header / cookie flag checks
│   ├── robots.py               # robots.txt / sitemap.xml recon
│   ├── fingerprint.py           # signature-based tech fingerprinting
│   ├── exposure_checks.py        # opt-in curated sensitive-path probe
│   ├── scoring.py                 # severity -> 0-100 risk score
│   ├── planner.py                  # agentic (Claude tool-use) + offline planner
│   ├── report.py                    # JSON / console / Markdown rendering
│   └── cli.py                        # argparse entry point
├── data/
│   ├── signatures.json       # tech fingerprint signature database
│   └── exposure_paths.json    # curated sensitive-path list
├── examples/
│   └── sample_report.md      # example Markdown output
└── tests/                     # pytest, all HTTP/LLM calls mocked
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## How the agentic planner works

The planner fetches the target's root page exactly once. In agentic mode,
that response (status, headers, a body excerpt) is handed to Claude along
with a small toolbox: `run_header_audit`, `run_recon_files_scan`,
`run_fingerprint`, and — only if `--enable-exposure-checks` was passed —
`run_exposure_check`. The model calls one tool per turn, sees the result,
and decides what to call next; it can stop after any tool once it judges
it has enough to report on. Two safety properties are enforced in code,
not just in the prompt: a tool that isn't offered this run can never be
invoked even if the model asks for it, and each tool can only run once per
scan. The loop is capped at 6 steps as a hard backstop.

## Limitations / possible extensions

- The exposure-path probe uses a simple "200 with a non-empty body" and
  "401/403" heuristic; it will false-positive against apps that return
  200 for every path (some SPA fallback routing does this) — verify hits
  manually before treating them as confirmed.
- TLS/certificate inspection (expiry, weak ciphers, hostname mismatch)
  isn't implemented yet; would be a natural next module in the same
  tool-registry shape as the existing ones.
- Signatures and exposure paths are illustrative starting sets, not
  exhaustive — both are plain JSON and easy to extend.
- No authentication/session handling — this is unauthenticated,
  pre-login recon only.
