# Web Recon Auditor

A passive HTTP attack-surface reconnaissance tool for **authorized**
penetration-testing and bug-bounty engagements. Point it at a target and it
produces a structured attack-surface report: missing/misconfigured security
headers, exposed sensitive paths (`.git/`, `.env`, backup files, admin
panels, ...), and TLS posture (weak protocol, expiring/expired
certificate) — optionally narrated by an LLM, grounded strictly in the
findings the deterministic checks already produced.

> **Authorized use only.** This tool sends live HTTP requests to a target
> you specify, including probes for exposed backup files, credentials, and
> admin panels. Only run it against systems you own or have explicit
> written authorization to test. The CLI refuses to run at all unless you
> pass `--authorized` (or set `WEBRECON_AUTHORIZED=1`), so that's never an
> accident.

## Why this exists

Recon is the first phase of any pentest engagement, and most public
"security header checker" demos stop at a handful of `if header not in
response` checks. This project pushes a bit further on the things that
distinguish a real recon tool from a toy:

- **Soft-404 baselining.** Many apps return HTTP 200 with a catch-all "not
  found" page for *any* route, which would make a naive sensitive-path
  scanner flag every single probe as "exposed". This tool first fingerprints
  the host's actual 404 behavior (status + response length) against a
  random, guaranteed-nonexistent path, then only reports a sensitive path as
  a real hit when it looks meaningfully different from that baseline —
  the same technique tools like `gobuster`/`ffuf` use to avoid drowning in
  false positives.
- **Diminishing-returns risk scoring.** Five "missing Permissions-Policy"
  findings across five subdomains isn't five times the risk of the same
  underlying gap — the scorer weights repeats of the same severity with
  decay instead of naive addition.
- **Grounded LLM narrative, same pattern as the rest of this repo.** The
  model only ever sees the structured findings, never raw traffic, and is
  explicitly told not to invent findings beyond that evidence. Without
  `ANTHROPIC_API_KEY`, the tool still produces a complete report via a
  deterministic offline summary — no key or network access required to use
  the tool fully.

## Checks performed

| Category | What it checks |
|---|---|
| Headers | HSTS, CSP (presence + `unsafe-inline` script-src), clickjacking protection (X-Frame-Options / `frame-ancestors`), X-Content-Type-Options, Permissions-Policy, `Server`/`X-Powered-By` version-banner disclosure, cookie flags (`Secure`, `HttpOnly`, `SameSite`) |
| Paths | `.git/config`, `.git/HEAD`, `.env`, AWS credentials, private SSH keys, config/DB backups, `phpinfo.php`, `server-status`, common admin panels, and RFC 9116 `/.well-known/security.txt` — full list in [`data/sensitive_paths.txt`](data/sensitive_paths.txt) |
| TLS | Negotiated protocol version (flags SSLv2/SSLv3/TLSv1.0/TLSv1.1), certificate expiry (expired = critical, expiring within 30 days = medium) |

## Quickstart

```bash
cd web-recon-auditor
pip install -e ".[dev]"        # add ".[llm]" for a live Claude-written summary

pytest -q

webrecon example.com --authorized                       # you must own/be authorized for this target
webrecon https://example.com --authorized --format json --out report.json
webrecon example.com --authorized --llm                 # needs ANTHROPIC_API_KEY
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m webrecon.cli example.com --authorized
```

## Example output

```
# Attack Surface Report: https://example.com

**Scanned at:** 2026-09-12T09:09:44+00:00
**Overall risk:** 🟠 HIGH (score 59/100)
**LLM-backed summary:** no (offline heuristic fallback)

## Findings
### 🟡 [MEDIUM] Missing Content-Security-Policy header
- **Category:** headers
- **Detail:** No CSP was set, so the browser enforces no restriction on
  which scripts/styles/frames the page may load — a key mitigation for
  reflected and stored XSS is absent.
- **Recommendation:** Define a restrictive CSP (at minimum script-src and
  object-src) scoped to the origins the app actually needs.

### ⚪ [INFO] Server discloses a version number
- **Category:** headers
- **Detail:** Server: "nginx/1.18.0" — gives an attacker a head start on
  matching known CVEs to the exact software version in use.
- **Recommendation:** Suppress or genericize the Server header at the
  reverse proxy/web server config.
```

## Project layout

```
web-recon-auditor/
├── webrecon/
│   ├── fetcher.py         # injectable HTTP client; never raises, captures errors
│   ├── headers.py          # security header checks
│   ├── paths.py             # sensitive-path probing + soft-404 baselining
│   ├── tls_check.py          # protocol/cert-expiry check via stdlib ssl+socket
│   ├── scoring.py             # findings -> 0-100 risk score with decayed repeats
│   ├── llm_summarizer.py       # grounded Claude narrative + offline fallback
│   ├── scanner.py                # orchestrates all checks into one ScanReport
│   ├── report.py                  # JSON/Markdown rendering
│   └── cli.py                      # argparse entry point + authorization gate
├── data/sensitive_paths.txt
├── tests/                            # pytest; a real local HTTP server fixture
│                                        drives the end-to-end scanner tests
└── examples/
```

## Design notes / limitations

- **Passive/low-noise by design.** This is a recon aid, not a fuzzer or
  exploit tool — it makes a small, fixed number of GET requests per target
  (one per header/path check, plus one TLS handshake). It does not attempt
  authentication bypass, injection, or brute forcing.
- **Sensitive-path list is illustrative, not exhaustive.** Swap in a larger
  wordlist via `--paths-file` for a real engagement; `data/sensitive_paths.txt`
  is deliberately small and readable for this demo.
- **Soft-404 baselining is a heuristic**, not a guarantee — a host that
  returns wildly different content lengths for different real 404s (e.g. a
  dynamic "did you mean...?" page) can still produce occasional false
  positives. Treat every finding as a lead to verify manually, not a
  confirmed vulnerability.
- **TLS check is a single handshake**, not a full cipher-suite audit. For a
  production engagement, pair this with `testssl.sh`/`sslyze` for exhaustive
  cipher and protocol coverage.

## Testing

```bash
pytest -q
```

55 tests cover every header/path/TLS/scoring/report rule in isolation, an
end-to-end scan against a real local HTTP server (exercising the soft-404
baselining logic against actual sockets), and the CLI itself as a
subprocess — including the authorization gate. No external network access
is required or performed by the test suite.
