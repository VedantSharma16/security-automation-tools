# Recon Agent

An agentic passive-recon assistant for authorized security testing. Given a
target domain, it gathers DNS, HTTP, and TLS recon and produces a scored,
analyst-facing report — using a genuine LLM tool-calling loop when an API
key is available, and a deterministic offline plan when it isn't.

## Why this exists

The other tools in this repo (`ioc-triage-assistant`, `log-triage-assistant`)
use an LLM to *narrate* a fixed, pre-computed pipeline: extract, enrich,
score, then ask the model to summarize the result. That's a common and
useful shape, but it isn't what "agentic" usually means. This project is
the other shape: the model is handed a set of tools and a goal, and it
decides — one step at a time, from the actual result of the previous step —
what to check next. An MX record present prompts a TXT lookup for SPF; a
fingerprinted legacy server prompts a closer look at the TLS config. That
loop, not the final write-up, is the interesting part, and it's implemented
from scratch against the Anthropic Messages API (~90 lines in `agent.py`),
not through an agent framework, so the control flow is fully inspectable.

It also intentionally covers different security ground than the rest of the
repo: those tools are blue-team / SOC triage over logs and alerts; this one
is early-stage, passive-only red-team recon — the reconnaissance phase of a
pentest engagement, scoped to checks that never touch anything beyond a
DNS query, one GET request, and a TLS handshake.

## Ethics / scope

This tool performs **passive reconnaissance only**: DNS lookups, a single
HTTP GET, a robots.txt fetch, and a TLS handshake to read the certificate.
It does not port-scan, brute-force, fuzz, or exploit anything. Even so,
running any recon against a domain requires authorization — the CLI refuses
to run without an explicit `--i-have-authorization` flag, which you should
only pass for domains you own or have written permission to test.

## How the agent loop works

```
target domain
      │
      ▼
 agent.py ── with ANTHROPIC_API_KEY: send SYSTEM_PROMPT + TOOL_SPECS to
      │        Claude; while stop_reason == "tool_use": dispatch the
      │        requested tool via tools.py, feed the real result back as a
      │        tool_result, let the model decide the next call (up to
      │        max_iterations); final text response is the narrative.
      │
      │      without a key (or if the SDK isn't installed): run every tool
      │        once via a fixed OFFLINE_PLAN, then build the narrative with
      │        a template over the structured findings — no LLM call, fully
      │        offline and deterministic.
      ▼
 tools.py ── ToolRegistry dispatches dns_lookup / http_headers /
      │        robots_check / tls_check and keeps every raw finding, so the
      │        report is built from ground truth, never from what the model
      │        claims it did.
      ▼
 scoring.py ── additive risk score from missing security headers, exposed
      │          fingerprinting headers, sensitive robots.txt paths, and
      │          TLS issues (expired/expiring certs, weak protocols)
      ▼
 report.py ── Markdown or JSON report
```

The recon primitives themselves are dependency-light and written from
scratch rather than wrapped around a scanner:

- **`dns_client.py`** is a ~150-line DNS client implementing RFC 1035 wire
  format directly with `struct` — query encoding, response parsing, and
  name-decompression pointer handling — for A/AAAA/MX/TXT/NS records. No
  `dnspython`.
- **`http_recon.py`** audits response headers against a small set of
  security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy) and pulls Disallow/Sitemap entries out of robots.txt.
- **`tls_recon.py`** connects with certificate validation deliberately
  disabled (a recon tool needs to inspect self-signed and expired certs,
  not refuse to look at them) and parses the raw DER bytes with
  `cryptography` — `ssl.SSLSocket.getpeercert()`'s dict form is only
  populated for certs that pass validation, so it silently comes back
  empty for exactly the certs worth inspecting.

Every network touchpoint (the UDP socket, the `urllib` opener, the TLS
connector) is dependency-injected, so the full test suite runs offline with
no network access and no API key.

## Quickstart

```bash
cd recon-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live agent loop
pytest -q

recon-agent example.com --i-have-authorization
recon-agent example.com --i-have-authorization --json
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m recon_agent.cli example.com --i-have-authorization
```

### Enabling the live agentic loop

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
recon-agent example.com --i-have-authorization
```

Without a key, the report's run mode reads
`offline deterministic plan`; with one, `agentic LLM tool-use loop`, and the
tool-call list in the report reflects whatever sequence the model actually
chose rather than the fixed plan.

## Example output

See [`examples/sample_report.md`](examples/sample_report.md) for a full
report (synthetic target, generated through the real `report.py` renderer)
showing a high-risk finding set: an outdated, fingerprinted web server,
missing security headers, robots.txt-disclosed internal paths, and a
deprecated TLS protocol.

```
🔴 **Risk: HIGH** (score 13) — run mode: agentic LLM tool-use loop

## Findings
- (+1) Missing security header: strict-transport-security
- (+2) Server fingerprinting headers exposed (server=Apache/2.2.15)
- (+2) robots.txt discloses sensitive-looking path: /admin
- (+3) Weak/deprecated protocol negotiated: TLSv1.1
```

## Project layout

```
recon-agent/
├── recon_agent/
│   ├── dns_client.py   # from-scratch DNS wire-format client
│   ├── http_recon.py    # security-header audit + robots.txt recon
│   ├── tls_recon.py      # TLS cert inspection via cryptography
│   ├── tools.py           # tool schemas + registry the agent calls
│   ├── agent.py            # the ReAct-style tool-calling loop + offline fallback
│   ├── scoring.py           # additive risk scoring over findings
│   ├── report.py             # Markdown / JSON rendering
│   └── cli.py                  # argparse CLI + authorization gate
├── examples/sample_report.md
└── tests/                        # pytest, fully offline, network points mocked
```

## Design notes / limitations

- **Offline plan is fixed; live plan is adaptive.** The offline fallback
  runs every tool once in a sensible order since there's no model deciding
  otherwise — it's a safety net, not a demonstration of agentic behavior.
  The live loop is where tool selection is actually dynamic.
- **`--i-have-authorization` is a self-attestation, not an enforcement
  mechanism.** It exists to make unauthorized use a deliberate choice
  rather than an accident, the same way `nmap` prints its legal-use notice.
- **Risk scoring is a heuristic**, in the same spirit as the other tools in
  this repo: small, explainable additive rules over the same four checks a
  human would eyeball first, not a vulnerability verdict.
- **DNS resolves against a fixed public resolver (`8.8.8.8`)** rather than
  the system resolver, so results are reproducible and independent of the
  local machine's DNS configuration; pass a different `server` to
  `dns_client.resolve()` to use another one.

## Testing

```bash
pytest -q
```

42 tests cover DNS wire-format encoding/parsing (including name
decompression and TXT chunking, using hand-built response packets), the
HTTP header/robots.txt checks, TLS certificate parsing (using real
short-lived certs generated with `cryptography` in the test fixtures),
scoring, the offline and live agent loops (the live loop is exercised
against a fake Anthropic client simulating multi-round tool use, including
a mid-run API failure and hitting `max_iterations`), report rendering, and
the CLI. No network access or API key is required to run the suite.
