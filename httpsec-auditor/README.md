# httpsec-auditor

A passive, zero-dependency HTTP security auditor. It checks a target's
response headers, cookies, CORS policy, and TLS configuration against
well-established web security baselines (OWASP Secure Headers, RFC 8996,
common CORS misconfiguration patterns), and produces a scored,
remediation-oriented report.

Think of it as a small, self-contained, script-friendly cousin of tools
like Mozilla Observatory or securityheaders.com — built from scratch on
just the Python standard library.

**Only run this against hosts you own or are explicitly authorized to
test.** It only ever issues passive `GET`/`OPTIONS` requests and a TLS
handshake — no exploitation, no brute forcing, no traffic volume beyond a
handful of requests — but scanning systems without authorization is
inappropriate (and often illegal) regardless of how gentle the tool is.

## Why this exists

Header/cookie/CORS/TLS misconfiguration is some of the highest-frequency,
lowest-effort-to-fix web exposure out there — missing `HttpOnly`, a
reflected-origin CORS policy, an expiring certificate — and being able to
audit for it quickly, explain *why* each finding matters, and hand back a
remediation is a core piece of both pentesting recon and blue-team hardening
work. This project demonstrates that end-to-end, plus the "read raw
protocol data, reason about it, score it" pattern that shows up constantly
in security tooling.

## Features

- **Security headers** — HSTS (presence, `max-age` floor,
  `includeSubDomains`), CSP (presence, `unsafe-inline`/`unsafe-eval`,
  wildcard sources), `X-Content-Type-Options`, clickjacking protection
  (`X-Frame-Options` or CSP `frame-ancestors`), `Referrer-Policy`,
  `Permissions-Policy`, and info-disclosure headers (`Server`,
  `X-Powered-By`, etc.).
- **Cookies** — flags cookies missing `Secure`, `HttpOnly`, or `SameSite`,
  and `SameSite=None` without `Secure`. Cookies whose name looks
  session/auth-related (`session`, `auth`, `token`, `jwt`, ...) are held to
  a stricter severity bar.
- **CORS** — sends a request with an arbitrary, attacker-looking `Origin`
  header and checks whether the server reflects it back (with or without
  `Access-Control-Allow-Credentials: true`), or pairs a wildcard origin
  with credentials — the two classic CORS misconfiguration patterns.
- **TLS** — inspects the negotiated protocol version and cipher suite for
  deprecated/weak choices (RFC 8996: TLS 1.0/1.1, RC4/3DES/NULL/EXPORT/MD5),
  certificate expiry (including an early-warning window), and
  hostname/SAN coverage.
- **Scoring** — a 0–100 score and A–F grade from a straightforward
  severity-weighted penalty model, plus a per-severity finding count.
- **Console and JSON output**, a `--min-severity` filter that also drives
  the process exit code (for CI/cron gating), and a `--json-out` flag that
  always writes the *full* report regardless of the console filter.
- **Zero runtime dependencies** — only `urllib`, `ssl`, and `socket` from
  the standard library. `pytest` is the only dev dependency.
- 59 unit tests. Every analyzer (`headers`, `cookies`, `cors`,
  `tls_inspector.analyze`, `scoring`, `report`) is a pure function over
  plain data, so the whole suite runs offline against synthetic
  headers/cookies/certificates — no network access or live target
  required. Only `fetcher.fetch()` and `tls_inspector.inspect()` touch the
  network, and the CLI orchestration layer is tested by mocking exactly
  those two seams.

## Installation

```bash
cd httpsec-auditor
pip install -e ".[dev]"   # or just run it directly, there are no runtime deps
```

## Usage

```bash
# Full audit: headers, cookies, CORS probe, and TLS
python -m httpsec.cli https://example.com

# Only report medium severity and above, disable color, write full JSON
python -m httpsec.cli https://example.com --min-severity medium --no-color --json-out report.json

# Skip the TLS check (e.g. auditing a plain-HTTP internal service)
python -m httpsec.cli http://internal.example --no-tls

# Skip the extra CORS probe request
python -m httpsec.cli https://example.com --no-cors

# Self-signed / staging certificate, don't verify chain
python -m httpsec.cli https://staging.example --insecure

# Use a custom probe Origin for the CORS check
python -m httpsec.cli https://api.example.com --origin https://attacker.example
```

Exit codes: `0` = no findings at or above `--min-severity` (default: every
finding, since the default is `info`), `1` = findings reported, `2` = a
fatal error (e.g. DNS failure, connection refused, TLS handshake failure).

Sample console output (see [`examples/sample_report.json`](examples/sample_report.json)
for the full JSON form of the same run, generated against mocked responses):

```
httpsec-auditor report for https://example-shop.test/
Score: 0/100  Grade: F
Findings: 1 critical, 3 high, 7 medium, 2 low, 2 info

[CRITICAL] CORS policy reflects an arbitrary Origin  (cors/cors-reflects-arbitrary-origin)
    The server echoed back an unrecognized probe origin ('https://untrusted-probe.httpsec-auditor.example')
    verbatim in Access-Control-Allow-Origin with credentials allowed. This effectively allows any website
    to make cross-origin requests to this endpoint and read the response using the victim's session cookies.
    Remediation: Validate the Origin header against an explicit allowlist server-side before reflecting it;
    never reflect unknown origins, especially alongside Allow-Credentials.
    Evidence: probe Origin: https://untrusted-probe.httpsec-auditor.example -> Access-Control-Allow-Origin: ...

[HIGH] Missing Strict-Transport-Security header  (headers/header-missing-hsts)
    ...
```

## Project layout

```
httpsec-auditor/
├── httpsec/
│   ├── models.py         # Finding / FetchResult / TLSInfo dataclasses
│   ├── fetcher.py         # network boundary: GET/OPTIONS over HTTP(S)
│   ├── tls_inspector.py    # TLS handshake + certificate inspection & analysis
│   ├── headers.py           # security header analysis (pure)
│   ├── cookies.py             # Set-Cookie flag analysis (pure)
│   ├── cors.py                  # CORS misconfiguration analysis (pure)
│   ├── scoring.py                 # severity-weighted score + letter grade
│   ├── report.py                    # console + JSON rendering
│   └── cli.py                         # argparse entry point / orchestration
├── tests/
│   ├── test_headers.py
│   ├── test_cookies.py
│   ├── test_cors.py
│   ├── test_tls_inspector.py
│   ├── test_scoring.py
│   ├── test_report.py
│   └── test_cli.py
├── examples/
│   └── sample_report.json
├── conftest.py
└── pyproject.toml
```

The design deliberately keeps every analyzer a pure function over plain
data (`dict` of headers, a list of `Set-Cookie` strings, a `TLSInfo`
snapshot) and confines all network I/O to two functions in `fetcher.py`
and one in `tls_inspector.py`. That's what makes the whole rule set
testable without a live target, matching the pattern used across this
repo's other tools.

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Possible extensions

- Add a `--compare-baseline` mode to diff a site's score/findings against
  a previous run and highlight regressions (useful for CI on your own
  infra).
- Check subresource-adjacent headers like `Cross-Origin-Opener-Policy` /
  `Cross-Origin-Embedder-Policy` / `Cross-Origin-Resource-Policy`.
- Add an HTTP→HTTPS upgrade check (does the plain-HTTP origin redirect to
  HTTPS at all, and does it do so before setting any cookies).
- Batch mode: read a list of URLs from a file and emit one JSON report per
  target plus a rolled-up summary table.
