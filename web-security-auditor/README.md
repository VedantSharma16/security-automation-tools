# web-security-auditor

A command-line tool that performs a **passive** external security assessment
of a web application: security headers, cookie flags, TLS certificate
health, and common accidentally-exposed paths (`.git/HEAD`, `.env`,
`server-status`, backup files, ...). It aggregates everything into a single
risk-scored report, in JSON or a human-readable console format.

"Passive" is a deliberate design constraint: every check is a plain GET
request, the same thing a browser or crawler would send. There is no
exploitation, brute forcing, payload injection, or fuzzing anywhere in this
tool — it answers "what does this site expose to any anonymous visitor?",
which is the first question in any authorized web app assessment.

## Ethical use

This tool sends live requests to the target, including probes for
known-sensitive paths. **Only run it against systems you own or are
explicitly authorized to test** (e.g. a scoped pentest engagement, your own
infrastructure, or a deliberately vulnerable lab like DVWA/juice-shop). The
CLI enforces this with a required `--authorized` flag — it refuses to run
without it.

## What it checks

| Category | Examples | Reference |
|---|---|---|
| Security headers | Missing HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, clickjacking protection | OWASP Secure Headers Project |
| Information disclosure | `Server` / `X-Powered-By` banners revealing software versions | - |
| Cookies | Missing `Secure`, `HttpOnly`, `SameSite` flags | OWASP Session Management |
| TLS | Expired/soon-to-expire certificate, weak negotiated protocol (< TLS 1.2) | - |
| Exposure | `.git/HEAD`, `.env`, `.svn/entries`, Apache `server-status`, WordPress config backups, `.DS_Store`; plus informational checks for `robots.txt` and `security.txt` | Common misconfiguration classes |

Findings are weighted by severity (INFO -> CRITICAL) into a 0-100 risk
score and an overall rating, where any single CRITICAL or HIGH finding
dominates the rating regardless of the aggregate score — one exposed
`.git` directory is a critical finding no matter how good the rest of the
posture looks.

## Install

```bash
cd web-security-auditor
pip install -e .          # core tool
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
webauditor https://example.com --authorized
webauditor example.com --authorized --json report.json --quiet
webauditor https://example.com --authorized --skip-tls --skip-exposure   # headers/cookies only
webauditor https://internal-app.local:8443 --authorized --timeout 15
```

The process exit code is `1` if any HIGH or CRITICAL finding was reported,
`0` otherwise — convenient for wiring into CI as a lightweight regression
gate on security headers.

See [`examples/sample_console_output.txt`](examples/sample_console_output.txt)
and [`examples/sample_report.json`](examples/sample_report.json) for what a
report looks like (built from a fabricated `demo.example.com` finding set,
not a live scan).

## Architecture

```
webauditor/
  fetcher.py       transparent HTTP GET wrapper (identifying User-Agent, no raised exceptions)
  headers.py       response headers + Set-Cookie -> Finding list
  tls_check.py     TLS handshake -> certificate/protocol Finding list
  exposure.py      fixed list of known-sensitive paths -> Finding list
  scoring.py       Finding list -> severity breakdown + 0-100 risk score + rating
  report.py        findings -> structured report dict, JSON/console rendering
  cli.py           argparse entry point wiring the above together, authorization gate
```

Every checker is a pure function from data to `Finding` objects (see
`webauditor/findings.py`) - none of them import each other, and none of
them perform I/O directly except through the injected `fetch` function.
That makes the whole suite testable without ever touching the network: the
test suite fakes `requests.Session`, `ssl`/`socket`, and the exposure
fetch callback, so `pytest` runs fully offline and deterministically.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

56 tests cover header/cookie analysis, TLS certificate evaluation (healthy,
expired, expiring-soon, weak-protocol cases), exposure detection (including
false-positive avoidance for empty 200 responses and network errors),
scoring/rating thresholds, report rendering, the HTTP fetch wrapper
(including multi-cookie handling), and the CLI end-to-end (authorization
gate, exit codes, `--json`/`--quiet`/`--skip-*` flags).

## Why this design

Real-world recon tools (`httpx`, `nikto`, `testssl.sh`) split cleanly into
"gather signal" and "score/report" phases, and stay strictly passive by
default so they're safe to run early and often in an engagement. This
project mirrors that shape at a much smaller scale: a handful of
independent, unit-tested checkers feeding a shared severity model, with an
explicit authorization gate baked into the CLI rather than left as a
README warning nobody reads before running the tool.
