# Web Recon Scanner

A single-target web reconnaissance tool that pulls together the checks a
pentester or bug-bounty hunter runs by hand in the first few minutes against
a web app: security response headers, TLS certificate/protocol health,
lightweight technology fingerprinting, `robots.txt`/sitemap review, and
optional DNS subdomain brute-forcing — as one CLI with a single graded
report.

> **Authorized use only.** This tool sends live HTTP, TLS, and DNS requests
> to whatever target you give it, including a subdomain brute-force option.
> Only run it against systems you own or have explicit written authorization
> to test. The CLI refuses to run unless you pass `--i-own-this-target`.

## Why this exists

Recon is the first phase of both a pentest and an incident-response
"what does our external footprint look like" exercise. This project
demonstrates that side of the security-automation/red-team spectrum,
complementing the blue-team/DFIR tools elsewhere in this repo
(`log-triage-assistant/`, `process_threat_hunter/`). It's built the same
way as those: a small pure-logic core (fully unit tested, no network
required) wrapped by a thin CLI that does the actual I/O.

## Features

- **Security header analysis** — checks for `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and `Permissions-Policy`; flags weak configurations
  (e.g. CSP with `unsafe-inline`, a short HSTS `max-age`), not just
  presence/absence. Also flags `Server`/`X-Powered-By`-style headers that
  leak implementation details, and `Set-Cookie` entries missing
  `Secure`/`HttpOnly`/`SameSite`.
- **TLS/certificate inspection** — expiry (and "expiring soon"), not-yet-valid
  certs, self-signed detection, and deprecated protocol negotiation
  (SSLv2/SSLv3/TLSv1/TLSv1.1).
- **Technology fingerprinting** — a small JSON signature set
  (`data/tech_signatures.json`) matched against response headers and HTML,
  in the spirit of Wappalyzer but dependency-free and easy to extend.
- **`robots.txt` / sitemap review** — surfaces `Disallow`ed paths that hint
  at something sensitive (`/admin`, `/.git`, `/backup`, ...) and pulls URLs
  out of any linked sitemap. Sitemap URLs are extracted with a regex
  instead of an XML parser deliberately: a sitemap is attacker-influenced
  input on a hostile target, and even stdlib `ElementTree` is a known
  XXE/billion-laughs vector unless hardened — the regex approach avoids
  that vulnerability class entirely.
- **Optional subdomain enumeration** — concurrent DNS brute-force against a
  bundled ~100-word list (`data/subdomain_wordlist.txt`) or your own,
  opt-in via `--enumerate-subdomains` since it's the most active/noisy check.
- **Weighted risk scoring** — every non-informational finding contributes to
  an overall score and letter grade (A–F) so results are skimmable at a
  glance, with full detail in the JSON report.
- **Automation-friendly exit codes** — `0` clean, `1` findings reported,
  `2` fatal error — so it can gate a CI step or scheduled scan.
- 46 unit tests covering every check module in isolation (no real network
  calls in the test suite) plus the CLI orchestration logic against a fake
  HTTP session.

## Installation

```bash
cd web-recon-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Refuses to run without this — see the disclaimer above
python -m webrecon.cli example.com --i-own-this-target

# Explicit scheme/port, write the full JSON report
python -m webrecon.cli https://example.com:8443 --i-own-this-target --json-out report.json

# Also brute-force common subdomains (slower, more active)
python -m webrecon.cli example.com --i-own-this-target --enumerate-subdomains

# Custom subdomain wordlist, shorter timeout, no ANSI color
python -m webrecon.cli example.com --i-own-this-target \
    --enumerate-subdomains --subdomain-wordlist my_words.txt \
    --timeout 5 --no-color
```

Exit codes: `0` = no findings, `1` = findings reported, `2` = fatal error
(target unreachable and no partial results at all).

See [`examples/sample_report.md`](examples/sample_report.md) for an
annotated example of the console output.

## Project layout

```
web-recon-scanner/
├── webrecon/
│   ├── headers.py       # security header + cookie flag analysis (pure)
│   ├── tls_check.py     # certificate/protocol inspection (pure) + live fetch
│   ├── fingerprint.py   # header/HTML technology signature matching (pure)
│   ├── robots.py        # robots.txt + sitemap.xml parsing (pure)
│   ├── subdomains.py    # concurrent DNS brute-force (injectable resolver)
│   ├── report.py        # aggregation, risk scoring, console/JSON rendering
│   └── cli.py            # argparse entry point, orchestrates the above
├── data/
│   ├── tech_signatures.json
│   └── subdomain_wordlist.txt
├── examples/
│   └── sample_report.md
├── tests/
├── requirements.txt
└── requirements-dev.txt
```

Every check module besides `cli.py` is pure — it takes plain data
(headers dict, cert dict, HTML string, wordlist) in and returns
dataclasses/lists out, with no network I/O of its own. `cli.py` is the only
module that touches sockets, and it's structured so a fake HTTP session can
be substituted in tests (`webrecon.cli.run(args, session=...)`).

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Possible extensions

- Add an authenticated-scan mode (cookie jar / bearer token) for
  post-login header and cookie checks.
- Expand `data/tech_signatures.json` with JS framework version detection
  (not just presence).
- Add a `--compare` mode that diffs two JSON reports for the same target
  over time, to catch newly-exposed paths or a downgraded TLS config.
