# recon-assistant

A small network-reconnaissance and attack-surface triage tool for
**authorized** penetration-testing / red-team engagements: it runs an async
TCP port scan, passively fingerprints what's listening from banners alone,
audits any web ports for missing HTTP security headers, scores the overall
risk, and produces an analyst-facing report — with an LLM-written narrative
when available, and a deterministic offline fallback when it isn't.

It's the offensive-security counterpart to this repo's other triage tools
(`log-triage-assistant`, `ioc-triage-assistant`, `process_threat_hunter`),
which are all blue-team/detection focused. Same pipeline shape — deterministic
checks first, LLM narrates on top, never the other way around — applied to
the recon side of an engagement instead.

## ⚠️ Authorized use only

This tool actively connects to network hosts. **Only run it against systems
you own or have explicit written authorization to test.** Unauthorized
scanning of systems you don't control may be illegal.

As a default-deny guardrail against pointing it at the wrong host by
accident, the tool **refuses to scan any target that doesn't resolve to a
private/loopback address** unless you pass `--confirm-authorized`:

```
$ recon-assistant scanme.example.com
error: 'scanme.example.com' resolves to 93.184.216.34, which is not a
private/loopback address. Refusing to scan without --confirm-authorized.
Only scan systems you own or have explicit written authorization to test.
```

This is a best-effort check (an IP-range test, not real authorization
enforcement) — it exists to stop accidents, not to replace a signed scope
document.

## Pipeline

```
target (host/IP)
      │
      ▼
authorization guardrail  (private/loopback, or --confirm-authorized)
      │
      ▼
async TCP connect-scan + banner grab  (scanner.py)
      │
      ▼
passive service fingerprinting        (fingerprint.py)
  - cleartext protocols (Telnet, FTP)
  - outdated OpenSSH banners
  - exposed databases (MySQL, Postgres, Redis, Mongo, ...)
  - exposed admin surfaces (SMB, RDP)
      │
      ▼
HTTP(S) security-header audit         (http_audit.py)
  - missing HSTS / CSP / X-Frame-Options / etc.
  - plaintext HTTP, verbose Server header
      │
      ▼
risk scoring + structured report      (scoring.py, report.py)
      │
      ▼
narrative summary: Claude, or offline template fallback  (llm_summarizer.py)
      │
      ▼
Markdown / JSON report
```

Every fingerprinting and header check is **passive**: it only looks at
whether a port accepted a connection and what it said first (or, for web
ports, the headers on a single HEAD request). Nothing here attempts
authentication, sends exploit payloads, or brute-forces credentials — that's
the boundary between recon and active exploitation, and this tool stays on
the recon side of it.

## Install

```bash
cd recon-assistant
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
# Scan a host you control on your own LAN — no confirmation flag needed.
recon-assistant 192.168.1.50

# Custom port list/ranges, JSON output to a file.
recon-assistant 10.0.0.5 --ports 22,80,443,8000-8010 --format json --out report.json

# Only surface medium+ severity findings.
recon-assistant 10.0.0.5 --min-severity medium

# A target you have written authorization to test, outside private ranges.
recon-assistant your-authorized-target.example.com --confirm-authorized

# LLM-written narrative (falls back to the offline template if no API key).
export ANTHROPIC_API_KEY=sk-...
recon-assistant 10.0.0.5 --llm
```

Exit codes (so it can gate a CI job or pre-deployment check): `0` clean scan,
`1` findings reported, `2` error (authorization refused, DNS failure, etc).

## Example output (offline mode, no API key)

```markdown
# Recon Report — 10.0.0.5 (10.0.0.5)

Ports scanned: 27  |  Open: 3  |  Risk score: 33/100  |  Highest severity: HIGH

## Open ports

| Port | Banner |
|---|---|
| 22 | SSH-2.0-OpenSSH_6.6p1 Ubuntu |
| 80 | HTTP/1.1 200 OK ... |
| 6379 | _(no banner)_ |

## Findings

| Severity | Port | Title | Recommendation |
|---|---|---|---|
| HIGH | 6379 | Redis reachable on this network path | Confirm Redis exposure ... |
| MEDIUM | 22 | Outdated OpenSSH version banner | Verify the patch level ... |
| LOW | 80 | Missing X-Frame-Options | Set X-Frame-Options: DENY ... |

## Analyst Narrative

[offline template narrative, or Claude-generated with ANTHROPIC_API_KEY set]
```

## Design notes

- **Async, not threaded.** The scanner runs on `asyncio` with a bounded
  `Semaphore`, so a few hundred ports scan concurrently under one event
  loop instead of spawning a thread per port.
- **Fully testable offline.** The scanner's connection factory and the
  header-auditor's fetch function are both injectable, so the test suite
  exercises real concurrency/timeout/banner-parsing/header logic against
  in-memory fakes — no sockets, no network, no flakiness in CI.
- **LLM narrates, never investigates.** The model only ever sees the
  already-computed JSON report, with a system prompt that explicitly forbids
  inventing hosts, ports, or CVEs beyond what's in that JSON — the same
  grounding pattern as this repo's other triage tools.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

48 tests covering port-spec parsing, the authorization guardrail, the async
scanner (via fake connections), passive fingerprinting rules, the HTTP
header audit, risk scoring, report rendering, the LLM/offline summarizer
split, and the CLI end-to-end.
