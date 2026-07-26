# websec-scanner

A small, authorized-use web application security scanner: security-header
and cookie-flag analysis, sensitive-file/path exposure probes, passive
technology fingerprinting, and opt-in active checks for reflected XSS and
error-based SQL injection.

## Why this exists

The rest of this repo has been blue-team-leaning: process/host detection
and alert triage. This project is the offensive-security counterpart --
the kind of lightweight recon/DAST tooling a pentester runs early in an
engagement to map obvious misconfigurations before manual testing. It's
built the same way as the other tools here: a small rule/check engine,
structured findings, JSON/Markdown reporting, and a pytest suite that
exercises every check against a real (locally-hosted, deliberately
vulnerable) target rather than mocks alone.

## ⚠️ Authorized use only

This tool sends real HTTP requests to the target, and its `--active` mode
sends extra requests designed to reveal reflected-XSS and SQL-injection
behavior. **Only run it against systems you own or have explicit written
authorization to test.** The CLI refuses to scan anything unless you pass
`--authorized`, which is a confirmation flag, not a technical control --
you are responsible for having real authorization. Active checks are
non-destructive (reflection/error-message detection only; no state-changing
payloads, no exploitation, no data exfiltration) but are still live traffic
against the target and should be treated like any other pentest activity.

## Features

- **Security header analysis** -- flags missing `Content-Security-Policy`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
  clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`), and
  missing `Strict-Transport-Security` on HTTPS targets. Also flags version
  disclosure via `Server`/`X-Powered-By`.
- **Cookie flag analysis** -- parses raw `Set-Cookie` headers (preserving
  duplicates, unlike naively concatenated headers) and flags cookies
  missing `Secure` (HTTPS targets), `HttpOnly`, or a safe `SameSite` value.
- **Sensitive path/file exposure probes** -- non-destructive GETs for
  `.git/config`, `.git/HEAD`, `.env`, `.svn/entries`, backup files,
  `phpinfo.php`, `server-status`, private key files, etc., with
  content-signature checks to avoid false positives from custom 404 pages.
- **`robots.txt` recon** -- surfaces `Disallow`/`Allow` paths as an
  informational lead (not itself a vulnerability).
- **Passive technology fingerprinting** -- `Server`/`X-Powered-By` headers,
  HTML `<meta name="generator">`, and known content signatures (WordPress,
  Drupal, Joomla, Django, ASP.NET WebForms).
- **Opt-in active checks (`--active`)** -- a small same-origin crawler
  (links + GET forms) discovers URL parameters, then probes each with a
  unique marker for reflected XSS and a single-quote payload for
  error-based SQL injection, matching against a set of common DB error
  signatures.
- **JSON and Markdown reports**, severity filtering, colored console
  output, and automation-friendly exit codes (`0` clean, `1` findings,
  `2` error / refused).
- 38 pytest tests, all running against a real (in-process, Flask-based)
  vulnerable target -- not just mocks -- so header parsing, cookie parsing,
  crawling, and injection detection are exercised end-to-end.

## Installation

```bash
cd websec-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Passive scan only (headers, cookies, exposure probes, fingerprinting).
python -m websec.cli https://example.com --authorized

# Also crawl the site and run active XSS/SQLi probes.
python -m websec.cli https://example.com --authorized --active

# Only show medium+ severity findings, write JSON + Markdown reports.
python -m websec.cli https://example.com --authorized --min-severity medium \
    --json-out report.json --md-out report.md

# Limit crawl depth and per-request timeout for a slow/large site.
python -m websec.cli https://example.com --authorized --active --max-pages 50 --timeout 15
```

Exit codes: `0` = no findings (after `--min-severity` filtering),
`1` = findings reported, `2` = refused (missing `--authorized`) or a fatal
error (e.g. invalid URL).

## Project layout

```
websec-scanner/
├── websec/
│   ├── models.py         # Finding / Severity / Endpoint dataclasses
│   ├── checks/
│   │   ├── headers.py     # security header analysis
│   │   ├── cookies.py     # Set-Cookie flag analysis
│   │   ├── exposure.py    # sensitive file/path probes + robots.txt parsing
│   │   ├── fingerprint.py # passive technology fingerprinting
│   │   └── injection.py   # reflected XSS / SQLi probe logic
│   ├── crawler.py         # same-origin link + GET-form crawler
│   ├── scanner.py         # orchestrates checks into a ScanResult
│   ├── report.py          # console / JSON / Markdown rendering
│   └── cli.py             # argparse entry point + authorization gate
├── tests/
│   ├── vulnerable_app.py  # deliberately-misconfigured Flask test target
│   ├── conftest.py        # spins the target up on a local port per session
│   └── test_*.py
├── requirements.txt
└── requirements-dev.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The test suite starts a small Flask app on an ephemeral localhost port with
known-bad configuration (missing headers, an `HttpOnly`-less cookie, an
exposed `.git/config`, a reflected-XSS parameter, a SQL-error-triggering
parameter) and runs the real scanner against it -- no live network calls to
third-party hosts happen during tests.

## Limitations / possible extensions

- Injection checks are limited to GET parameters and cover reflection /
  error-message detection only -- no blind/time-based SQLi, no stored XSS,
  no header/cookie/JSON-body injection points, no auth-aware crawling
  (forms requiring login won't be reached).
- No TLS/certificate inspection (expiry, weak ciphers, hostname mismatch).
- No rate limiting beyond a per-request timeout; a very large `--max-pages`
  against a slow target will simply take longer, not back off.
- Could add authenticated scanning (cookie/header injection for the whole
  session), a `--respect-robots` mode, and a small ruleset of known CVEs
  keyed off fingerprinted technology/version.
