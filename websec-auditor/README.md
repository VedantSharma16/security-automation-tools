# websec-auditor

A passive web security posture auditor: it fetches a single URL the same
way a browser would, then grades the response's HTTP security headers,
cookie flags, and TLS/certificate configuration -- similar in spirit to
Mozilla Observatory or securityheaders.com, but as a small, from-scratch,
scriptable/CI-friendly CLI.

## Why this exists

The rest of this repo is blue-team/IR-flavored (log triage, IOC triage,
process hunting). Pentesting and red-team work starts the same place every
engagement does: passive recon of the target's external attack surface.
This tool is that first step -- a safe, non-intrusive check of what a
server's own responses reveal about its security posture -- built to also
double as a CI gate for teams shipping their own web apps.

**Scope, deliberately:** this tool performs one GET request (plus, only if
you opt in, a couple of standard files like `/robots.txt`) -- the same
requests any browser or search-engine crawler makes. It does not
brute-force paths, guess credentials, fuzz inputs, or attempt exploitation.
Only point it at hosts you own or are explicitly authorized to test.

## Features

- **Security header analysis** -- Content-Security-Policy, Strict-Transport-Security
  (with `max-age` sanity checks), X-Content-Type-Options, clickjacking
  protection (X-Frame-Options / CSP `frame-ancestors`), Referrer-Policy,
  Permissions-Policy, and Server/X-Powered-By version disclosure.
- **Cookie flag checks** -- Secure, HttpOnly, and SameSite on every
  `Set-Cookie` header (correctly handling multiple cookies, which a naive
  `dict(headers)` implementation silently drops).
- **TLS/certificate check** -- negotiated protocol version (flags TLS 1.1
  and below), certificate expiry (flags expired and soon-to-expire certs).
- **Lightweight tech fingerprinting** -- from headers, cookie names, and a
  few body markers (WordPress, Drupal, Django, Laravel, Express, Rails,
  ASP.NET, etc.), entirely from data already in the response.
- **A-F grade + 0-100 score**, weighted by finding severity, so results are
  comparable across scans.
- **JSON and Markdown reports**, plus a `--fail-on <severity>` flag so it
  can gate a CI pipeline (non-zero exit if a finding at or above that
  severity is present).
- Every network call is routed through one small, injectable module
  (`fetcher.py`); the entire test suite (59 tests) runs fully offline
  against fake HTTP/TLS responses -- no real sockets, no live targets
  required to verify correctness.

## Installation

```bash
cd websec-auditor
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a URL, print a Markdown report to stdout
websec-auditor scan https://example.com

# Also check robots.txt and /.well-known/security.txt
websec-auditor scan example.com --check-well-known

# Write JSON (for tooling) and Markdown (for humans) reports to files
websec-auditor scan https://example.com --json report.json --markdown report.md

# CI gate: exit 1 if anything medium-or-worse is found
websec-auditor scan https://example.com --fail-on medium

# Skip the TLS check (e.g. auditing an internal HTTP-only service)
websec-auditor scan http://internal.example --skip-tls
```

Exit codes: `0` = clean (or no `--fail-on` threshold crossed), `1` =
`--fail-on` threshold reached, `2` = the target could not be reached or the
URL was invalid.

Sample output:

```
# Web Security Audit: https://example.com/

**Final URL:** https://example.com/
**HTTP status:** 200
**Grade:** D (63/100)

## Fingerprint
- Server: nginx

## Findings
- [HIGH] **headers** — No Strict-Transport-Security header on an HTTPS response.
    - Recommendation: Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' ...
- [MED]  **headers** — No Content-Security-Policy header present.
    - Recommendation: Add a Content-Security-Policy restricting script/style/object sources ...
- ...
```

## Project layout

```
websec-auditor/
├── websec_auditor/
│   ├── fetcher.py       # injectable HTTP layer (list-of-tuples headers, never raises)
│   ├── headers.py       # security header + cookie flag rule engine
│   ├── tls_check.py     # TLS protocol/cert expiry check (injectable connector)
│   ├── fingerprint.py   # passive technology fingerprinting
│   ├── findings.py      # shared Finding model + severity weights
│   ├── scoring.py       # findings -> 0-100 score -> A-F grade
│   ├── audit.py         # orchestrates fetch -> analyze -> score into an AuditResult
│   ├── report.py        # Markdown / JSON rendering
│   └── cli.py           # argparse entry point
└── tests/
    ├── fakes.py          # fake HTTP opener/response (no real sockets)
    ├── test_fetcher.py
    ├── test_headers.py
    ├── test_tls_check.py
    ├── test_fingerprint.py
    ├── test_scoring.py
    ├── test_audit.py
    ├── test_report.py
    └── test_cli.py
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Possible extensions

- Add authenticated scanning (send a session cookie to audit the
  logged-in state of an app you're testing).
- Multi-URL/sitemap-driven batch scans with an aggregate score.
- Optional integration with a real vulnerability scanner (e.g. Nuclei) as
  a separate, explicitly-opt-in, authorization-gated mode -- kept out of
  this tool on purpose to keep the default behavior strictly passive.
