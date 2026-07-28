# Attack Surface Mapper

An authorized external recon tool: passively enumerates a domain's
subdomains via certificate transparency logs, then actively audits each
resolved host for common exposures (open sensitive ports, missing HTTP
security headers, weak/expiring TLS certificates) and rolls everything up
into a per-host risk score.

Where `process_threat_hunter` and `log-triage-assistant` are blue-team /
detection tools and `ioc-triage-assistant` is alert-analysis, this one is
the offensive/recon side of the same workflow: the kind of external
attack-surface sweep a pentester or red-teamer runs at the start of an
engagement, or a defender runs against their own org to see what's
actually exposed.

## ⚠️ Authorized use only

This tool performs **active** network probing (TCP connections, HTTP
requests, TLS handshakes) against whatever host you point it at. Only run
it against systems you own or have explicit written authorization to
test — e.g. a bug bounty program's in-scope assets, or your own
infrastructure. Unauthorized scanning of third-party systems may be
illegal in your jurisdiction.

To make that a deliberate step rather than an accident, the CLI enforces
it in software:

- **Passive discovery** (crt.sh certificate-transparency lookup + DNS
  resolution) always runs — it only queries a public log aggregator and
  never contacts the target.
- **Active checks** (port scan, HTTP header audit, TLS cert check) are
  skipped unless you pass `--i-am-authorized`. Without it, you get the
  subdomain list and a clear notice, and the process exits cleanly.

## Features

- **Passive subdomain enumeration** via the [crt.sh](https://crt.sh) certificate-transparency
  JSON API, with wildcard stripping, dedup, and apex-domain filtering.
- **Threaded DNS resolution** of discovered hostnames.
- **TCP port scan** against a curated common-service port list (not a full
  1–65535 sweep), flagging ports that are rarely meant to be
  internet-facing (RDP, databases, Telnet, SMB, ...) as "sensitive."
- **HTTP security header audit** — HSTS, CSP, clickjacking protection,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` — plus
  `Server`/`X-Powered-By` version-disclosure detection.
- **TLS certificate expiry check** — flags expired, imminently-expiring,
  and soon-to-expire certificates.
- **Per-host risk scoring** (0–100 + info/low/medium/high/critical level)
  combining all of the above, with console (colorized) and JSON report
  output.
- **Safety rails**: an explicit authorization flag gating all active
  checks, plus a `--max-hosts` cap so a large subdomain list doesn't
  trigger an unbounded scan by default.
- 50 unit tests, all running against mocked network/socket/TLS layers —
  no real network access required to run the test suite.

## Installation

```bash
cd attack-surface-mapper
pip install -e .
```

No third-party runtime dependencies — everything is built on the Python
standard library (`socket`, `ssl`, `urllib`, `concurrent.futures`).

## Usage

```bash
# Passive-only: list subdomains discovered via certificate transparency
attack-surface-mapper example.com --passive-only

# Full scan (passive discovery + active port/header/TLS checks),
# only after confirming you're authorized to test the target
attack-surface-mapper example.com --i-am-authorized

# Scan a single known host directly, skipping subdomain discovery
attack-surface-mapper host.example.com --skip-discovery --i-am-authorized

# Custom port list, cap on how many resolved hosts get actively scanned,
# and a JSON report for downstream tooling
attack-surface-mapper example.com --i-am-authorized \
    --ports 22,80,443,8080 --max-hosts 10 --json-out report.json
```

Exit codes: `0` clean, `1` if any open ports or findings were reported,
`2` on a discovery/network error — so it can gate a CI step or scheduled
job the same way the other tools in this repo do.

### Sample output

```
Discovered 3 host(s) via passive enumeration:
  example.com -> 93.184.216.34
  mail.example.com -> 93.184.216.35
  www.example.com -> 93.184.216.34

[HIGH    ] www.example.com (93.184.216.34)
           risk score: 32/100
           open ports: 443/https
           [high    ] Missing Strict-Transport-Security
                      HTTPS is available but HSTS is not enforced — allows protocol
                      downgrade to plaintext HTTP on subsequent visits.
           [medium  ] TLS certificate expiring soon
                      Certificate expires in 12 day(s) (2026-08-09).
```

See [`examples/sample_report.json`](examples/sample_report.json) for a
full JSON report shape.

## Architecture

```
attack_surface_mapper/
├── models.py       # Subdomain, OpenPort, Finding, HostReport dataclasses
├── subdomains.py   # crt.sh lookup, parsing, DNS resolution (passive)
├── portscan.py     # threaded TCP connect-scan (active)
├── httpaudit.py    # security header + banner audit (active)
├── tlsaudit.py     # TLS cert expiry check (active)
├── scoring.py       # per-host risk score/level aggregation
├── report.py       # console + JSON rendering
└── cli.py          # orchestration + authorization gate
```

Every module that touches the network takes its I/O dependency
(`fetcher`, `resolver`, `connector`, `opener`) as an injectable parameter
defaulting to the real implementation — that's what lets the entire test
suite run offline against mocks instead of live infrastructure.

## Testing

```bash
pip install -e ".[dev]"
pytest
```
