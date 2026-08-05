# web-security-auditor

A passive HTTP security posture scanner — checks security headers, cookie
flags, and TLS configuration for one or more URLs and produces a graded
report, in the spirit of [securityheaders.com](https://securityheaders.com)
/ Mozilla Observatory, runnable locally, scriptable in CI, and fully
unit-testable offline.

Where the other tools in this repo are detection/blue-team focused (parsing
logs, watching processes), this one is recon/hardening-validation focused —
the kind of pass you'd run at the start of a web app pentest, or in a CI
pipeline to catch a header regression before it ships.

> **Scope note:** this tool only ever sends a normal HTTP GET request — the
> same thing a browser does when you visit a page — and a direct TLS
> handshake to read the certificate. It performs no exploitation, fuzzing,
> or brute forcing. Still, only point it at systems you own or are
> authorized to assess.

## What it checks

| Category | Checks |
|---|---|
| **Transport** | HTTPS is actually used (or HTTP upgrades to it), HSTS present with a sane `max-age` and `includeSubDomains` |
| **Headers** | `Content-Security-Policy` (present, no `unsafe-inline`/`unsafe-eval`, has a `default-src`/`script-src`), `X-Content-Type-Options: nosniff`, clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy`, `Server`/`X-Powered-By` version disclosure |
| **Cookies** | Every `Set-Cookie` is checked for `Secure`, `HttpOnly`, and `SameSite` (and the `SameSite=None` without `Secure` foot-gun) |
| **TLS** | Direct socket probe of the negotiated protocol version and certificate expiry — flags deprecated protocols (SSLv2/3, TLS 1.0/1.1) and certs that are expired or expiring soon |

Each finding carries a severity (`info`/`low`/`medium`/`high`/`critical`)
and a concrete recommendation. Findings roll up into a 0–100 score and a
letter grade (A+ down to F), the same shape recruiters/hiring managers will
recognize from public header-grading tools.

## Install

```bash
cd web-security-auditor
pip install -r requirements.txt
```

## Usage

```bash
# Scan a single site
python -m websecaudit.cli https://example.com

# Scan several sites and write a combined JSON + Markdown report
python -m websecaudit.cli https://example.com https://api.example.com \
    --json-out report.json --md-out report.md

# Batch mode from a file (one URL per line, # comments allowed)
python -m websecaudit.cli --input-file assets.txt

# Fail CI if any site's grade drops below B (default threshold is C)
python -m websecaudit.cli https://example.com --min-grade B

# Point at an internal/self-signed host
python -m websecaudit.cli https://internal.corp --insecure --no-tls-probe
```

Sample output:

```
web-security-auditor — https://example.com
Status: 200   Scheme: https
Grade: F   Score: 34/100
Findings: 12

[HIGH    ] cookie-missing-secure (cookie)
           Cookie 'session' is missing the Secure attribute on an HTTPS site.
           -> Add the Secure attribute so the cookie is never sent over plain HTTP.
...
```

### Exit codes

Designed to slot into a CI job the same way the other tools in this repo do:

| Code | Meaning |
|---|---|
| `0` | Every scanned site met `--min-grade` (default `C`) |
| `1` | At least one site scored below `--min-grade` |
| `2` | A site could not be reached, or a fetch error occurred |

## Design

- **`fetcher.py`** is the only module that touches the network (an HTTP
  `GET` via `requests`, plus a direct TLS socket probe for certificate/
  protocol details). Everything downstream — `headers.py`, `cookies.py`,
  `tls.py`, `grading.py` — is a set of pure functions over plain
  dataclasses, so the entire rule set is unit tested against fixtures
  with **no network access required**.
- **`scanner.analyze()`** orchestrates fetch results through all three
  checkers and grading into a single `ScanResult`.
- **`report.py`** renders the same `ScanResult` as colored console output,
  JSON, or Markdown.
- **`cli.py`** takes an injectable `fetch` function (defaults to
  `fetcher.fetch`), which is how `tests/test_cli.py` exercises the full
  argument-parsing/exit-code/file-output path without any network or
  monkeypatched sockets.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

79 tests covering header/cookie/TLS rule logic, grading boundaries, report
rendering, the network layer (mocked `requests`/`ssl`/`socket`), and the CLI
end to end — all offline.
