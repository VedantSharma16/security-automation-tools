# http-security-auditor

A passive HTTP security posture auditor for a single target URL: security
headers, cookie flags, CORS misconfiguration, and TLS certificate/protocol
health, rolled up into a weighted 0-100 score and letter grade (A-F), plus
an LLM-generated, remediation-prioritized narrative (with a fully offline
deterministic fallback).

Built as an AppSec/pentest-recon tool — the kind of quick posture check
you'd run at the start of an authorized web application engagement, or
wire into CI to catch header regressions before they ship.

> **Only scan systems you are authorized to test.** This tool makes real
> HTTP(S) requests to the target you give it. `--check-exposed` issues a
> handful of *additional* requests to well-known paths (`/.git/HEAD`,
> `/.env`, etc.) on that same host to check for accidental exposure — it
> never scans or discovers hosts beyond the one you specify.

## What it checks

| Category | Checks |
|---|---|
| **Headers** | HSTS (presence + `max-age`), Content-Security-Policy (presence + `unsafe-inline`/`unsafe-eval`), `X-Content-Type-Options: nosniff`, clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy`, `Server`/`X-Powered-By` version disclosure |
| **Cookies** | `Secure` (on HTTPS), `HttpOnly`, `SameSite`, evaluated per-cookie |
| **CORS** | Wildcard `Access-Control-Allow-Origin` combined with `Access-Control-Allow-Credentials: true` (critical), bare wildcard on its own (low), scoped-origin sanity checks |
| **TLS** | Negotiated protocol version (flags SSLv2/SSLv3/TLSv1.0/TLSv1.1), certificate expiry (critical if expired, warn under 30 days) |
| **Exposure** *(opt-in via `--check-exposed`)* | Common secret/config leaks: `.git/HEAD`, `.env`, `.aws/credentials`, WordPress config backups, and presence of `.well-known/security.txt` |

Findings are weighted by severity (`critical`/`high`/`medium`/`low`/`info`/`pass`)
into a single score, which maps to a letter grade the same way
[securityheaders.com](https://securityheaders.com)-style tools do.

## Install

```bash
cd http-security-auditor
pip install -e .          # core tool, stdlib only
pip install -e ".[llm]"   # + anthropic SDK for live LLM narratives
pip install -e ".[dev]"   # + pytest
```

## Usage

```bash
http-audit --url https://example.com
http-audit --url https://example.com --json
http-audit --url https://example.com --markdown
http-audit --url https://example.com --check-exposed   # authorized targets only
```

Example human-readable output:

```
Grade: C  Score: 75/100  HTTP status: 200
LLM-backed: no (offline heuristic fallback)

Findings (11):
  🟢 [PASS] (headers) Strict-Transport-Security: HSTS present with max-age=63072000.
  🟠 [HIGH] (headers) Content-Security-Policy: No Content-Security-Policy header; ...
      -> Define a CSP that restricts script/style/object sources to trusted origins.
  🔴 [CRITICAL] (cors) CORS wildcard with credentials: Access-Control-Allow-Origin is '*' ...
      -> Return a specific, allow-listed origin instead of '*' whenever credentials are allowed.
  ...

Summary:
[offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis] Grade C (75/100).
Highest-priority issues: CORS wildcard with credentials (critical); Content-Security-Policy (high).
2 total issue(s) found across headers, cookies, CORS, and TLS checks. Fix critical/high findings
first (they represent direct exploitation or data-exposure risk), then medium/low findings as
defense-in-depth hardening.
```

Set `ANTHROPIC_API_KEY` to get a live, LLM-written remediation narrative
instead of the deterministic offline summary — no other behavior changes,
and the tool works fully offline without it.

## Design notes

- **Zero required dependencies.** The core audit pipeline (`fetcher`,
  `headers`, `cookies`, `cors`, `tls`, `exposure`, `scoring`) uses only the
  Python standard library (`http.client`, `ssl`, `http.cookies`).
- **Fully testable offline.** Every check function operates on a plain
  `HttpResponse` dataclass, not sockets — `run_audit()` accepts an injectable
  `transport` callable, so the whole pipeline (including `--check-exposed`)
  is exercised in tests with zero network access. See `tests/`.
- **CORS caveat.** The CORS check is passive: it inspects the CORS headers
  returned on a single plain request. A full CORS audit also actively
  probes with attacker-controlled `Origin` values to catch origin
  reflection; that's out of scope here to keep this a single-request,
  low-noise check.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
