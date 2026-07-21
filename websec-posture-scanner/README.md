# Web Security Posture Scanner

A passive web application security posture scanner. It fetches a URL,
inspects the response, and grades it (A-F, Mozilla Observatory style) on:

- **HTTP security headers** — HSTS, CSP, X-Content-Type-Options,
  clickjacking protection (X-Frame-Options / CSP `frame-ancestors`),
  Referrer-Policy, Permissions-Policy.
- **Cookie flags** — `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie`,
  with higher severity for cookies that look like session/auth tokens.
- **CORS misconfiguration** — reflected-Origin checks, wildcard origin
  combined with credentialed requests.
- **TLS** — protocol version, cipher, certificate expiry, self-signed
  detection.
- **Information disclosure** — `Server`, `X-Powered-By`, and similar
  headers that fingerprint backend versions for free.

## Why this exists

Most of the other tools in this repo are blue-team/detection focused. This
one is deliberately reconnaissance-flavored — the kind of first-pass
external assessment a pentester or AppSec engineer runs before diving
deeper — while staying **non-intrusive**: it never sends exploit payloads,
brute-forces paths, or does anything beyond standard GET requests and a TLS
handshake. That makes it safe to run against production systems, but you
should still only point it at hosts you are authorized to assess.

## Design notes

Network I/O (`webscan/fetcher.py`) is deliberately kept separate from the
checks (`webscan/checks/`). Every check is a pure function over an
already-fetched `ScanTarget`/`TLSInfo` dataclass, which is what makes the
whole check suite unit-testable without touching the network — the only
tests that open a real socket are in `test_fetcher.py`, and those talk to a
local `http.server` instance on loopback, not the internet.

**Known limitation:** when run with `--insecure` (skip TLS verification,
e.g. against a self-signed internal host), Python's `ssl` module
intentionally returns an *empty* certificate dict from `getpeercert()`
unless the chain validates — this is documented stdlib behavior, not a bug
here. In that mode you still get the negotiated protocol/cipher, but not
expiry/issuer/subject; those fields are only populated on a normal,
verified connection.

## Installation

```bash
cd websec-posture-scanner
pip install -e .
```

No third-party dependencies are required to run the scanner — it's built
entirely on the standard library (`urllib`, `ssl`, `socket`).

## Usage

```bash
# Scan (scheme defaults to https if omitted)
python -m webscan.cli example.com

# Write JSON and Markdown reports alongside the console output
python -m webscan.cli https://example.com --json report.json --markdown report.md

# Scan an internal host with a self-signed certificate
python -m webscan.cli https://internal.corp.example --insecure

# Skip the TLS handshake check (e.g. scanning behind a TLS-terminating proxy)
python -m webscan.cli https://example.com --no-tls-check

# Skip the extra CORS-probe request
python -m webscan.cli https://example.com --no-cors-probe

# CI gating: exit 1 if the grade is worse than B
python -m webscan.cli https://example.com --fail-below B
```

Exit codes: `0` = scan completed (and met `--fail-below`, if set), `1` =
grade fell below the `--fail-below` threshold, `2` = the scan itself
failed (DNS/connection/timeout error).

### Sample output

```
Web Security Posture Scan: https://example.com/
Grade: D  (score 48/100)
Findings: 6

TLS: TLSv1.3 / TLS_AES_256_GCM_SHA384 (expires in 214 days)

[HIGH    ] Missing Strict-Transport-Security header (headers)
    The site is served over HTTPS but does not send Strict-Transport-Security, ...
    Fix: Send `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on every HTTPS response.
...
```

## Grading

Each finding has a severity (`critical`/`high`/`medium`/`low`/`info`) that
deducts points from a starting score of 100:

| Severity | Deduction |
|---|---|
| critical | 25 |
| high | 15 |
| medium | 7 |
| low | 3 |
| info | 0 |

Score maps to a letter grade: A (>=90), B (>=75), C (>=60), D (>=40),
otherwise F.

## Project layout

```
websec-posture-scanner/
├── webscan/
│   ├── models.py      # Finding / ScanTarget / TLSInfo / ScanResult dataclasses
│   ├── fetcher.py      # the only module that touches the network
│   ├── checks/
│   │   ├── headers.py   # HSTS, CSP, X-Content-Type-Options, clickjacking, ...
│   │   ├── cookies.py    # Secure / HttpOnly / SameSite
│   │   ├── cors.py        # Origin reflection, wildcard + credentials
│   │   ├── tls.py          # protocol, expiry, self-signed
│   │   └── disclosure.py    # Server / X-Powered-By fingerprinting
│   ├── grading.py     # findings -> score -> letter grade
│   ├── report.py       # text / markdown / json rendering
│   └── cli.py            # argparse entry point
├── tests/
│   ├── test_headers.py, test_cookies.py, test_cors.py, test_tls.py,
│   │   test_disclosure.py   # pure-function checks, no I/O
│   ├── test_fetcher.py       # against a local http.server, no real network
│   ├── test_grading.py, test_report.py, test_cli.py
├── pyproject.toml
└── requirements-dev.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

62 tests, all offline — the fetcher tests spin up a throwaway
`http.server` on `127.0.0.1` rather than reaching out to the internet.

## Possible extensions

- Optional active checks (common sensitive paths like `/.git/HEAD`,
  `/.env`) behind an explicit opt-in flag, since those are more intrusive
  than pure header/TLS inspection.
- Subresource Integrity (SRI) checks on `<script>`/`<link>` tags in the
  response body.
- A `--compare` mode that diffs two scans (e.g. before/after a config
  change) and reports only what changed.
- Batch mode: scan a list of URLs from a file and emit one aggregate report.
