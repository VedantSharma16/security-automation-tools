# Web Security Auditor

A passive HTTP security posture scanner. Point it at one or more URLs and it
checks response headers, cookie flags, and TLS certificate health against
rules drawn from the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
and the Mozilla Observatory rule set, then rolls the findings up into an
A–F grade with concrete remediation advice.

## Why this exists

The other tools in this repo (`log-triage-assistant`, `ioc-triage-assistant`,
`process_threat_hunter`) are all blue-team/detection focused. This one covers
the recon and hardening-review side of the job: the kind of quick,
non-intrusive check a pentester runs before an engagement to map the
external attack surface, or a defender runs to verify hardening didn't
regress. It only ever sends a normal `GET` request and opens a standard TLS
handshake — no fuzzing, no exploitation, nothing that wouldn't show up as
routine traffic in a web server's access log.

**Only run this against hosts you own or are explicitly authorized to
test.**

## Features

- **HTTP security headers** — HSTS (including plain-HTTP awareness),
  Content-Security-Policy (flags `unsafe-inline`/`unsafe-eval`/wildcard
  sources), X-Content-Type-Options, clickjacking protection
  (X-Frame-Options or CSP `frame-ancestors`), Referrer-Policy,
  Permissions-Policy, and Server/X-Powered-By version disclosure.
- **Cookie hardening** — every `Set-Cookie` header is checked for `Secure`,
  `HttpOnly`, and `SameSite`.
- **TLS posture** — negotiates a real handshake to report protocol version
  (flags SSLv2/SSLv3/TLSv1.0/TLSv1.1 as insecure), cipher, and certificate
  expiry (critical if already expired, high if <14 days, medium if <30
  days).
- **Scoring** — each finding deducts points by severity; failures cost more
  than warnings. Produces a 0–100 score and an A–F letter grade.
- **CI-friendly** — `--min-grade` exits non-zero if any audited URL scores
  below the threshold, so it can gate a pipeline the same way a linter does.
- **JSON output** (`--json`) for piping into other tooling.
- Zero runtime dependencies — built entirely on the standard library
  (`urllib`, `ssl`, `socket`). 42 unit tests, all running against a local
  test HTTP server or mocked sockets — no external network calls in the test
  suite.

## Installation

```bash
cd web-security-auditor
pip install -e .
```

No third-party packages are required to run it; `pip install -e .` just
registers the `webauditor` console script.

## Usage

```bash
# Audit a single site
webauditor https://example.com

# Audit several sites, machine-readable output
webauditor https://example.com https://sub.example.com --json

# Skip the TLS handshake check (e.g. auditing an internal HTTP-only service)
webauditor http://internal.example.local --no-tls

# Gate a CI pipeline: fail the build if any target scores below a B
webauditor https://example.com --min-grade B
```

Sample output:

```
Target:   http://127.0.0.1:44495/
Status:   HTTP 200 (4 ms)
Grade:    F  (score 48/100)

Findings:
  [FAIL] [HIGH    ] Content-Security-Policy: No Content-Security-Policy header was sent.
           -> Define a CSP that restricts script, style, and object sources to trusted origins.
  [FAIL] [HIGH    ] Cookie Attributes: One or more cookies are missing security attributes: session missing Secure, HttpOnly, SameSite
           -> Set Secure, HttpOnly, and SameSite on every session/auth cookie.
  [FAIL] [MEDIUM  ] Clickjacking Protection: Neither X-Frame-Options nor a CSP frame-ancestors directive was found.
           -> Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive to prevent clickjacking.
  ...
  [PASS] [INFO    ] X-Content-Type-Options: nosniff set.
```

Exit codes: `0` normally; `1` if `--min-grade` is set and any target falls
below it.

## Project layout

```
web-security-auditor/
├── webauditor/
│   ├── models.py         # Finding/Severity/Status shared types
│   ├── fetcher.py        # stdlib-only HTTP client, redirect + header capture
│   ├── headers.py        # header/cookie rule checks
│   ├── tls_inspector.py  # TLS handshake + certificate checks
│   ├── scoring.py        # findings -> 0-100 score -> A-F grade
│   ├── auditor.py        # orchestrates fetch + checks + scoring per URL
│   ├── report.py         # text/JSON rendering
│   └── cli.py            # argparse entry point
├── tests/
│   ├── test_fetcher.py       # real requests against a local HTTPServer
│   ├── test_headers.py
│   ├── test_tls_inspector.py # mocked sockets, no real network
│   ├── test_scoring.py
│   ├── test_auditor.py
│   ├── test_report.py
│   └── test_cli.py
└── pyproject.toml
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Possible extensions

- Subresource Integrity (SRI) checks on `<script>`/`<link>` tags in the
  response body.
- CORS misconfiguration checks (`Access-Control-Allow-Origin: *` combined
  with credentialed requests).
- A `--compare` mode that diffs two scans of the same host to catch
  hardening regressions between deploys.
