# recon-agent

An agentic, read-only attack-surface reconnaissance assistant for
**authorized** security assessments — the offensive-security counterpart to
this repo's blue-team tools, and a demonstration of a genuine plan-act-observe
agent loop rather than a fixed pipeline.

> ⚠️ **For authorized use only.** Only ever point this at hosts you own or
> have explicit written permission to test. The CLI refuses to run unless
> you pass `--i-have-authorization`.

## Why this exists

The other tools in this repo (`log-triage-assistant`, `ioc-triage-assistant`,
`process_threat_hunter`) are all blue-team/detection tools. `recon-agent`
fills out the other half of the IR/pentest skill set — reconnaissance — and
does it with a different AI pattern than the rest of the repo: instead of a
RAG index (`ioc-triage-assistant`) or a static rule engine plus an LLM
narrative bolted on at the end (`log-triage-assistant`), this is a small
**agent**: it decides what to do next after every tool call, based on what
it has observed so far, from a fixed registry of read-only tools.

## How the agent loop works

```
target ──▶ Planner.next_action(session) ──▶ tool call ──▶ record result ──▶ repeat
                     │
                     ├─ offline (default): a deterministic policy that still
                     │  branches — e.g. it will not port-scan or fetch a TLS
                     │  cert for a hostname that failed to resolve
                     │
                     └─ live (ANTHROPIC_API_KEY set): an LLM chooses the next
                        tool from the registry given the results so far, and
                        can choose to "finish" early. Falls back to the
                        offline policy if the response is malformed, asks for
                        a tool already run, or the API call fails — the agent
                        can never get stuck.
```

Tool registry (all read-only, standard-library only):

| Tool | What it does |
|---|---|
| `dns_lookup` | Resolve the target hostname to an IPv4 address. |
| `subdomain_enum` | Brute-force a small wordlist of common subdomain labels against the target's DNS. |
| `port_scan` | Concurrent TCP connect-scan of common service ports, with best-effort banner grabbing. |
| `http_headers` | Fetch HTTP(S) response headers and audit them against a recommended security-header list. |
| `tls_cert` | Fetch the TLS certificate and check issuer/expiry. |

Results are aggregated into severity-scored findings (`report.py`) mapped
against a small local risk-rating dataset (`data/port_risk.json`,
`data/security_headers.json`), and a closing executive-summary narrative is
generated — by an LLM if `ANTHROPIC_API_KEY` is set, otherwise by a
deterministic offline fallback that highlights the worst finding. The tool
is fully functional and testable with zero API key and zero third-party
dependencies.

## Installation

```bash
cd recon-agent
pip install -e .          # stdlib only
pip install -e ".[llm]"   # optional: adds LLM-driven planning + narrative
```

## Usage

```bash
# Basic scan (subdomain enum + port scan + header/TLS audit)
recon-agent --target example.com --i-have-authorization

# Skip subdomain brute-forcing, use a tighter timeout
recon-agent --target example.com --i-have-authorization --no-subdomain-enum --timeout 2

# Only try the first 5 wordlist entries, scan a custom port list
recon-agent --target example.com --i-have-authorization --subdomain-limit 5 --ports 22,80,443,8080

# Full JSON report, also written to a file
recon-agent --target example.com --i-have-authorization --json --json-out report.json

# Cap the agent's tool budget
recon-agent --target example.com --i-have-authorization --max-steps 3
```

Exit codes: `0` = no high/critical findings, `1` = high or critical findings
present (so it can gate a CI job or scheduled scan), `2` = refused to run
(missing `--i-have-authorization`).

Set `ANTHROPIC_API_KEY` to switch both the planner and the final narrative
from the deterministic offline mode to live LLM calls — no other flags
needed.

## Project layout

```
recon-agent/
├── recon_agent/
│   ├── dns_recon.py     # DNS resolution + subdomain brute force
│   ├── port_scan.py      # concurrent TCP connect-scan + banner grab
│   ├── http_recon.py      # HTTP header audit + TLS certificate inspection
│   ├── agent.py             # plan-act-observe loop, offline policy + LLM planner
│   ├── report.py              # findings aggregation + risk scoring
│   ├── narrative.py             # LLM / offline executive summary
│   └── cli.py                     # argparse entry point
├── data/
│   ├── port_risk.json      # per-port severity ratings + rationale
│   └── security_headers.json  # recommended HTTP security headers
├── wordlists/
│   └── subdomains_small.txt
├── tests/                    # 39 tests, all mocked — no real network calls
└── pyproject.toml
```

## Design notes

- **Everything is dependency-injectable.** Every network call (`resolver`,
  `connector`, `fetcher`, `cert_getter`) takes a default real implementation
  but accepts an override, so the full test suite runs in well under a
  second with no sockets opened and no external services required.
- **Stdlib only for the core.** DNS via `socket.gethostbyname`, port
  scanning via `socket.create_connection` + a thread pool, HTTP via
  `urllib.request`, TLS inspection via `ssl.wrap_socket().getpeercert()`.
  The `anthropic` SDK is an optional extra used only for the planner and
  narrative.
- **The agent never gets stuck.** Every LLM-driven decision point has a
  deterministic fallback (malformed JSON, a hallucinated/repeated tool name,
  or an API failure all degrade to the offline policy instead of raising).

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Possible extensions

- Add a `subdomain_takeover` tool that flags dangling CNAMEs pointing at
  deprovisioned cloud resources.
- Add a `robots_txt` / `.well-known` crawler for a lightweight content
  discovery pass.
- Persist scan history and diff two runs against the same target to
  surface newly opened ports or newly expired certs over time.
