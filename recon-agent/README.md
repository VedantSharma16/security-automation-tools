# recon-agent

A passive, authorized-use-only attack-surface recon tool: given a domain, it
checks DNS hygiene, HTTP security headers, TLS certificate health, and
robots.txt disclosures, then scores the result and writes an analyst-facing
report — either with a fixed, deterministic tool order, or with an
**agentic** mode where Claude decides which tools to run and writes the
summary itself.

It's the AI-engineering counterpart to this repo's detection tools
(`log-triage-assistant`, `ioc-triage-assistant`, `process_threat_hunter`):
those score after-the-fact evidence; this one plans and drives its own
recon.

## Why this exists

Most "AI agent" demos hide the interesting part — how the model decides
what to do next — behind a framework. This project keeps it visible:

- **The tools are dumb and deterministic.** Each one (`dns_tool`,
  `headers_tool`, `tls_tool`, `robots_tool`) is a plain function with the
  network call isolated behind an injectable parameter, so the actual
  analysis logic (what counts as a missing security header, an expiring
  cert, a risky CORS policy) is fully unit-testable with no network access
  and no mocking framework.
- **The planning is swappable.** By default, `recon-agent` runs a fixed
  static plan (`planner.run_static`) — every tool, in a fixed order, no LLM
  involved. With `--agentic` and `ANTHROPIC_API_KEY` set, `planner.run_agentic`
  hands Claude the same tools through the Messages API's native tool-use
  loop: Claude sees each tool's result before deciding what to call next,
  skips tools it judges unnecessary, and writes the final analyst summary
  itself, grounded in the results it actually saw. Without an API key, it
  transparently falls back to the static plan and a templated offline
  summary — the tool is always fully usable without any API access.
- **Ethics is a code path, not a warning label.** The CLI refuses to run
  (`exit 2`) unless `--authorized` is passed, and every check performed is
  passive: DNS resolution, an HTTP GET, a TLS handshake, and reading the
  target's own robots.txt. Nothing here probes, brute-forces, or touches
  any path the target didn't already advertise.

## What it checks

| Tool | Checks |
|---|---|
| `dns_lookup` | A/AAAA resolution, SPF record, DMARC record (`_dmarc.<domain>`), nameserver redundancy |
| `http_headers` | HTTPS enforcement, HSTS, CSP, `X-Content-Type-Options`, clickjacking protection (`X-Frame-Options` / CSP `frame-ancestors`), `Referrer-Policy`, server/version banner disclosure, permissive CORS (flags `ACAO: *` + credentials as **critical**), cookie `Secure`/`HttpOnly`/`SameSite` flags |
| `tls_certificate` | Certificate expiry (critical if expired, high if <14 days, medium if <30), issuer/subject/SANs, weak negotiated protocol (TLS 1.0/1.1, SSLv2/3) |
| `robots_txt` | Disallowed paths that hint at sensitive functionality (`/admin`, `.git`, `.env`, `/wp-admin`, etc.) — read-only, never fetched |

Findings are weighted by severity into a 0–100 score and an A–F grade
(mirrors the Mozilla Observatory / securityheaders.com model).

## Install

```bash
cd recon-agent
pip install -e .           # core tool: dns_lookup, http_headers, tls_certificate, robots_txt
pip install -e ".[llm]"    # + agentic mode (anthropic SDK)
pip install -e ".[dev]"    # + pytest, for running the test suite
```

## Usage

```bash
# Refused: authorization must be explicit
recon-agent scan example.com

# Static plan, Markdown report to stdout
recon-agent scan example.com --authorized

# JSON report to a file
recon-agent scan example.com --authorized --format json --out report.json

# Agentic mode: Claude chooses tool order and writes the summary
export ANTHROPIC_API_KEY=sk-...
recon-agent scan example.com --authorized --agentic
```

Exit code is `1` if any finding was reported, `0` if the scan came back
clean — so it can gate a CI job or scheduled check. `--authorized` is
mandatory; omitting it exits `2` without making any network request.

**Only run this against a domain you own or have explicit written
permission to test.**

## Architecture

```
recon_agent/
  models.py     Finding / ToolResult / ReconReport dataclasses
  tools/
    dns_tool.py       DNS records -> findings   (network call injectable via query_fn)
    headers_tool.py   HTTP headers -> findings  (network call injectable via fetch_fn)
    tls_tool.py       TLS handshake -> findings (network call injectable via connect_fn)
    robots_tool.py    robots.txt -> findings    (network call injectable via fetch_fn)
  planner.py    static_plan() / run_static()  — fixed tool order, no LLM
                run_agentic()                 — Claude tool-use loop over the same tools
  executor.py   runs a plan, aggregates findings, scores, builds a ReconReport
  scoring.py    severity-weighted 0-100 score -> A-F grade
  report.py     Markdown / JSON rendering + deterministic offline narrative
  cli.py        `recon-agent scan <target> --authorized [--agentic] [--format] [--out]`
```

Every tool's network I/O is isolated behind a single injectable function
(`query_fn`, `fetch_fn`, `connect_fn`), so the 53-test suite runs in well
under a second with zero network access and zero mocking-framework
dependency — plain functions passed as arguments.

## Testing

```bash
pip install -e ".[dev]"
pytest
```
