# Web Security Auditor

A read-only HTTP security auditing tool, in the style of Mozilla Observatory
or SSL Labs: point it at a URL and it grades the target's security posture
across five dimensions — response headers, cookie flags, CORS
configuration, TLS/certificate health, and information disclosure — with a
letter grade, remediation advice per finding, and a JSON report for piping
into other tooling.

**Authorized use only.** This tool sends a small number of GET requests to
the target (a baseline request, plus optional CORS and sensitive-path
probes). It performs no exploitation, no brute forcing, and no writes. Only
run it against hosts you own or are explicitly authorized to test (your own
infrastructure, a bug bounty program in scope, a CTF target, a client
engagement) — the same standard that applies to any other passive/light-
active recon tool.

## Why this exists

Application-layer security misconfiguration — missing headers, permissive
CORS, cookies without `Secure`/`HttpOnly`, stale TLS — is one of the most
common findings in real web app pentests and bug bounty reports, and
catching it is a fast, repeatable, scriptable check that belongs in any
recon toolkit or CI pipeline. This project demonstrates that checklist as
working code: a small rule engine per dimension, a scoring model, and a
CLI, rather than a one-off manual walkthrough.

## What it checks

| Category | Checks |
|---|---|
| **Headers** | `Strict-Transport-Security` (presence + `max-age` floor), `Content-Security-Policy` (presence + `unsafe-inline`/`unsafe-eval`/wildcard sources), `X-Content-Type-Options: nosniff`, `X-Frame-Options` (or CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy`. |
| **Cookies** | Every `Set-Cookie` on the response is checked for `Secure` (on HTTPS), `HttpOnly`, and an explicit `SameSite`, including the `SameSite=None` without `Secure` case. |
| **CORS** | Re-requests the target with an arbitrary `Origin` header and checks whether `Access-Control-Allow-Origin` reflects it — especially alongside `Access-Control-Allow-Credentials: true`, which would let any third-party site read authenticated responses on behalf of a logged-in victim. |
| **TLS** | Negotiated protocol version (flags SSLv3/TLS 1.0/1.1) and certificate expiry (critical/high/medium/pass thresholds), via a direct handshake — handshake failures (invalid chain, self-signed, hostname mismatch) are themselves reported as findings. |
| **Disclosure** | Version-revealing response headers (`Server`, `X-Powered-By`, etc.) and whether a handful of commonly-exposed paths (`/.git/HEAD`, `/.env`, `/.aws/credentials`, `/wp-config.php.bak`) return `200` instead of being blocked. |

Every check produces a `pass`/`warn`/`fail`/`info` result with a severity,
a human-readable detail, and (for anything other than `pass`) a concrete
remediation. Results are aggregated into a 0–100 score and an A–F letter
grade (severity-weighted point deductions, floored at 0).

## Installation

```bash
cd web-security-auditor
pip install -e .
```

No third-party dependencies are required for the core tool — only the
Python standard library (`urllib`, `ssl`, `socket`).

## Usage

```bash
# Full audit, human-readable console report
python -m webaudit.cli https://example.com

# Write the full structured report to disk
python -m webaudit.cli https://example.com --json-out report.json

# Fully passive: skip the CORS and sensitive-path probe requests, only
# analyze the single baseline response (headers/cookies/TLS)
python -m webaudit.cli https://example.com --no-active-probes

# Disable ANSI color (e.g. for CI logs), custom timeout
python -m webaudit.cli https://example.com --no-color --timeout 5
```

Exit codes: `0` = no failing checks, `1` = at least one `fail`-status check
(useful as a CI gate on a staging deployment), `2` = the target could not
be reached at all.

Example console output:

```
Web Security Auditor — https://example.com/
Scanned at : 2026-09-11T09:00:00+00:00
Score      : 100/100 (grade A)
Checks     : 12 pass / 0 warn / 0 fail / 1 info

[PASS] Strict-Transport-Security — Present: max-age=31536000; includeSubDomains
[PASS] Content-Security-Policy — Present without common risky directives.
...
```

## Project layout

```
web-security-auditor/
├── webaudit/
│   ├── fetcher.py      # read-only HTTP fetch, TLS handshake, probe helpers
│   ├── headers.py       # security-header checks
│   ├── cookies.py        # Set-Cookie attribute checks
│   ├── cors.py             # CORS misconfiguration detection
│   ├── tls.py               # TLS protocol/certificate expiry checks
│   ├── disclosure.py         # banner + sensitive-path exposure checks
│   ├── report.py               # scoring, grading, console/JSON rendering
│   └── cli.py                   # argparse entry point
├── tests/
│   ├── test_headers.py, test_cookies.py, test_cors.py, test_tls.py,
│   │   test_disclosure.py, test_report.py   # pure unit tests, no network
│   └── test_cli.py                          # CLI wiring, fetcher mocked
└── pyproject.toml
```

Every check module operates on plain data (a headers dict, a list of raw
`Set-Cookie` values, a certificate's not-after date) rather than performing
I/O itself, so the entire rule engine is unit-tested without touching the
network. `fetcher.py` is the only module that makes real requests, and
`tests/test_cli.py` monkeypatches it to verify the CLI's wiring end to end.

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

57 tests, all offline.

## Possible extensions

- Subresource Integrity (SRI) checks on `<script>`/`<link>` tags in the
  response body.
- Concurrent scanning of a list of URLs (e.g. every host in scope for an
  engagement) with a combined summary report.
- A `--baseline`/diff mode like `process_threat_hunter/`, to alert only on
  posture regressions between two scans of the same target.
