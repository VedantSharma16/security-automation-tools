# Web Recon Toolkit

An authorized-use web application reconnaissance tool: it audits HTTP
security headers and cookie flags against OWASP guidance, probes for
accidentally-exposed sensitive files (`.git/config`, `.env`, backups,
admin/debug endpoints), and fingerprints server/framework technology from
response signals — then produces a severity-scored, remediation-oriented
report.

## Why this exists

The rest of this repo leans blue-team (log triage, endpoint process
hunting, IOC enrichment). This project fills out the offensive/pentesting
side: the first thing most external assessments and bug-bounty recon do is
exactly this — check headers, probe for leaked files, and fingerprint the
stack before diving into manual testing. It's built the same way as the
rest of the repo: a small rule/check engine, structured findings, a risk
score, and a full test suite that never depends on network access.

**Only run this against systems you own or have explicit written
permission to test.** The CLI and library both refuse to send a single
request unless the caller explicitly asserts authorization — there is no
way to scan a target "by accident."

## Features

- **Security header audit** — checks for `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Frame-Options` (or an equivalent CSP
  `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`, and
  `Permissions-Policy`; flags `Server`/`X-Powered-By`/ASP.NET version
  disclosure; checks every `Set-Cookie` for missing `Secure` / `HttpOnly`
  / `SameSite`. Each finding cites the relevant OWASP category and a
  concrete remediation.
- **Sensitive-path discovery** — probes a conservative, built-in wordlist
  of commonly-exposed files (VCS metadata, `.env`/credential files, config
  and database backups, Spring Boot actuator, `mod_status`, `phpinfo()`,
  etc.), with an automatic soft-404 baseline check so hosts that return
  HTTP 200 for everything (SPA catch-alls, custom error pages) don't
  produce false positives.
- **Tech fingerprinting** — informational (never a "vulnerability") signal
  extraction from `Server`/`X-Powered-By` headers, HTML `generator` meta
  tags, and known framework session-cookie names.
- **Risk scoring** — same severity/weight model as the other tools in this
  repo: a 0–100 risk score plus a per-severity breakdown.
- **Authorization gate** — `scan_target()` raises unless called with
  `authorized=True`; the CLI requires `--i-have-authorization`.
- **Automation-friendly exit codes** for CI/cron use.
- 35 tests, all running against an in-process `http.server` test fixture —
  no real network target is ever touched by the test suite.

## Installation

```bash
cd web-recon-toolkit
pip install -r requirements.txt
```

## Usage

```bash
# Markdown report to stdout
python -m webrecon.cli https://your-own-staging-host.example --i-have-authorization

# JSON report to a file, with a slower per-request delay for path discovery
python -m webrecon.cli https://your-own-staging-host.example \
    --i-have-authorization --format json --out report.json --delay 0.25
```

Exit codes: `0` = clean, `1` = findings reported, `2` = error (bad target,
missing authorization flag, or the request itself failed).

### As a library

```python
from webrecon.scanner import scan_target
from webrecon.report import build_report, to_markdown

result = scan_target("https://your-own-staging-host.example", authorized=True)
print(to_markdown(build_report(result)))
```

## Project layout

```
web-recon-toolkit/
├── webrecon/
│   ├── models.py       # Finding / ScanResult / Severity
│   ├── headers.py      # security header + cookie-flag checks
│   ├── paths.py        # sensitive-path discovery + soft-404 baseline
│   ├── fingerprint.py  # informational tech fingerprinting
│   ├── scoring.py      # severity breakdown + 0-100 risk score
│   ├── scanner.py       # orchestration + authorization gate
│   ├── report.py         # JSON/Markdown rendering
│   └── cli.py              # argparse entry point
├── tests/
│   ├── conftest.py      # in-process HTTP test server fixture
│   ├── test_headers.py
│   ├── test_paths.py
│   ├── test_fingerprint.py
│   ├── test_scanner.py
│   ├── test_report.py
│   └── test_cli.py
├── requirements.txt
└── requirements-dev.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Possible extensions

- Add a subdomain enumeration module (DNS wordlist + certificate
  transparency lookup) for a fuller external recon pass.
- Add active checks for common misconfigurations (open redirect probes,
  CORS wildcard-with-credentials, verbose error pages).
- Pull the sensitive-path wordlist from an external file so it can be
  swapped per-engagement without editing code.
