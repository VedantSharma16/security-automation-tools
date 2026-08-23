# websec-recon

An authorized external recon tool for web applications: subdomain
enumeration, TCP port scanning, HTTP security header analysis, and TLS
certificate checks, merged into a single scored report. Built entirely on
the Python standard library — no API keys, no third-party scanning
service, no dependencies to install for the core scan.

> **Authorized use only.** Only run this against hosts you own or have
> explicit written permission to test. Port scanning and probing systems
> without authorization can violate the law (e.g. the U.S. CFAA) and the
> target's terms of service, regardless of how passive the checks are.
> This tool performs a standard TCP connect-scan of common ports and
> resolves a small bundled subdomain wordlist — no exploitation, brute
> forcing of credentials, or denial-of-service behavior of any kind.

## Why this exists

The rest of this repo is blue-team leaning (log triage, IOC triage, host
process hunting). Recon is the other half of the loop: before you can
defend an attack surface, you need to know what it actually looks like
from the outside — the same first step an attacker or a pentester takes.
This project demonstrates that side: DNS/port/HTTP/TLS enumeration with
each check mapped to a concrete, explainable finding and remediation, the
same structure the blue-team tools in this repo use for their output.

## Features

- **Subdomain enumeration** — resolves `<word>.<domain>` for a ~70-entry
  bundled wordlist via standard DNS lookups (no traffic reaches the target
  host itself). Flags non-production/admin-facing subdomains (`dev.`,
  `staging.`, `admin.`, `vpn.`, ...) and likely wildcard DNS records.
- **Port scan** — threaded TCP connect-scan (no raw sockets/root required)
  across ~30 commonly-exposed ports, with best-effort banner grabbing.
  Flags high-risk exposures (Redis/MongoDB with no default auth, RDP, SMB,
  an unauthenticated Docker API, etc.) with a rationale for each.
- **HTTP security headers** — checks for HSTS, CSP (or an equivalent
  `frame-ancestors` directive), `X-Content-Type-Options`,
  `X-Frame-Options`, and `Referrer-Policy`; flags `Server`/`X-Powered-By`
  version disclosure and cookies missing `Secure`/`HttpOnly`/`SameSite`.
- **TLS certificate checks** — validates the certificate chain, flags
  expired/soon-to-expire certificates and deprecated protocol versions
  (SSLv2/v3, TLS 1.0/1.1).
- **Unified, scored report** — every check emits the same `Finding` shape
  (category, severity, description, recommendation, evidence); findings
  are aggregated into a single 0–100 risk score. Console (colored),
  Markdown, and JSON output.
- **Fully offline test suite** — every network call (DNS resolution,
  socket connect, HTTP fetch, TLS handshake) is behind a small injectable
  function, so all 47 tests run with no network access via fakes/mocks.

## Installation

```bash
cd websec-recon
# stdlib only — nothing to install for the core scan
pip install -r requirements-dev.txt  # only needed to run the tests
```

## Usage

```bash
# Full scan: subdomains, ports, headers, TLS
python -m recon.cli example.com

# Only show medium+ severity findings
python -m recon.cli example.com --min-severity medium

# Skip the subdomain sweep and port scan, just check headers + TLS
python -m recon.cli example.com --no-subdomains --no-ports

# Write JSON and Markdown reports
python -m recon.cli example.com --json-out report.json --md-out report.md
```

Exit codes: `0` = no findings (after `--min-severity` filtering), `1` =
findings reported — so it can gate a CI step or scheduled check.

## Example output

```
websec-recon — example.com — scanned 2026-08-23T09:00:00+00:00
Findings   : 4
Risk score : 45/100 (medium)

[CRITICAL] (ports) Port 6379 (redis) exposed
           Redis has no authentication by default and is routinely abused for RCE/cryptomining.
           fix: Firewall port 6379 to trusted source IPs only, or place it behind a VPN/bastion instead of exposing it directly.
[MEDIUM  ] (dns) Non-production or admin-facing subdomains exposed
           Subdomains commonly used for internal, admin, or non-production services resolve publicly: staging.example.com
           fix: Restrict these hosts to a VPN/allowlist, or confirm they are intentionally public and hardened to the same standard as production.
[MEDIUM  ] (http_headers) Missing Content-Security-Policy header
           Without a CSP, the browser has no defense-in-depth against injected/XSS scripts.
           fix: Set the Content-Security-Policy response header on https://example.com/.
[INFO    ] (http_headers) Server header discloses software details
           Server: nginx/1.18.0
           fix: Suppress or genericize the Server header to avoid handing attackers a shortlist of known CVEs to try.
```

## Project layout

```
websec-recon/
├── recon/
│   ├── findings.py     # shared Finding model + risk scoring
│   ├── dns_enum.py     # subdomain enumeration
│   ├── port_scan.py    # threaded TCP connect-scan + banner grab
│   ├── http_headers.py # HTTP security header analysis
│   ├── tls_check.py    # TLS certificate/protocol checks
│   ├── report.py        # console/Markdown/JSON rendering
│   └── cli.py            # argparse entry point
├── data/
│   └── subdomain_wordlist.txt
├── tests/
│   ├── test_findings.py
│   ├── test_dns_enum.py
│   ├── test_port_scan.py
│   ├── test_http_headers.py
│   ├── test_tls_check.py
│   ├── test_report.py
│   └── test_cli.py
├── requirements.txt      # empty — stdlib only
└── requirements-dev.txt  # pytest
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

47 tests, all offline — DNS resolution, socket connections, HTTP fetches,
and TLS handshakes are all injected as fakes, so the suite never touches
the network.

## How each check is scored

Every finding carries a severity (`info` → `critical`). The overall risk
score is a capped sum of per-severity weights (`findings.py`), so one
critical finding (e.g. an exposed, unauthenticated database) always
dominates the score rather than being diluted by a pile of informational
findings — the same principle `process_threat_hunter/` uses for its
`--min-severity` filtering.

## Possible extensions

- Certificate Transparency log lookup (e.g. crt.sh) as a passive
  alternative/complement to wordlist-based subdomain enumeration.
- Async I/O (`asyncio`) instead of thread pools for the port scan, to scale
  to larger port ranges without growing the thread count.
- An optional LLM-generated executive summary grounded in the structured
  findings, following the same pattern as `log-triage-assistant/` and
  `ioc-triage-assistant/` in this repo.
