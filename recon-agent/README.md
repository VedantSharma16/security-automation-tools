# Recon Agent

An agentic, passive attack-surface recon assistant. Given a target domain,
it investigates DNS, subdomain exposure, HTTP security headers, and TLS
certificate health, then produces a structured, severity-ranked findings
report with an analyst-facing summary — either written by an LLM that
decides for itself which tools to call and in what order, or, without an
API key, by a deterministic pipeline that calls every tool once.

> **Authorized use only.** This tool performs passive, read-only
> reconnaissance (DNS resolution, a small subdomain wordlist, an HTTP GET,
> a TLS handshake, a WHOIS lookup) — the same category of activity as
> `dig`, `curl -I`, or `openssl s_client`. It does not scan, brute-force,
> exploit, or attempt to bypass anything. Still: only ever point it at a
> domain you own or are explicitly authorized to test (e.g. as part of a
> scoped pentest or bug-bounty program).

## Why this exists

The other tools in this repo (`log-triage-assistant`, `ioc-triage-assistant`)
use an LLM for narrative generation or RAG retrieval, but the control flow
is always fixed by the code. This project demonstrates the other common
applied-AI pattern: an **agentic tool-use loop**, where the LLM itself
decides which of a fixed set of read-only tools to call, in what order, and
when it has gathered enough evidence to stop — the same architecture behind
real agentic security tooling (autonomous recon agents, SOC copilot
investigations, etc.), built here from scratch against the Claude API's
tool-use support rather than a heavyweight agent framework.

It's also the first tool in this repo aimed at the offense/recon side of
the pentest lifecycle rather than blue-team triage — deliberately scoped to
stay passive and safe to run against your own infrastructure.

## How the agent loop works

1. The model is given a system prompt describing its role and a target,
   plus JSON-schema descriptions of five tools (`dns_lookup`,
   `subdomain_enum`, `http_probe`, `tls_probe`, `whois_lookup`).
2. Each round, the model either requests one or more tool calls or writes
   a final summary. Requested tools are executed locally and their JSON
   results are fed back as `tool_result` messages.
3. This repeats — adaptively, e.g. only running `tls_probe` on hosts the
   model actually discovered via `subdomain_enum` — until the model stops
   requesting tools or a `--max-steps` budget is hit.
4. **Findings and severity are never left to the model.** Every raw tool
   result gathered during the run (agentic or offline) is run back through
   a deterministic rules module (`findings.py`) that flags missing security
   headers, expiring/expired certificates, weak TLS protocol versions, and
   sensitive-sounding exposed subdomains. The LLM only supplies the
   narrative layered on top of those facts — mirroring the
   facts-vs-narrative split used in `ioc-triage-assistant`.

Without `ANTHROPIC_API_KEY` set, step 1–3 are replaced by a fixed pipeline
that calls all five tools once in order — same findings engine, same report
shape, no adaptive tool selection.

## Quickstart

```bash
cd recon-agent
pip install -e ".[dev]"        # add ".[llm]" for the agentic mode, ".[whois]" for WHOIS

recon-agent --target example.com
recon-agent --target example.com --json
recon-agent --target example.com --max-steps 8   # agentic mode only

pytest -q
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m recon_agent.cli --target example.com
```

### Enabling the agentic mode

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
recon-agent --target example.com
```

Without a key, the report prints `Mode: offline deterministic pipeline` and
still produces a complete, structured report.

## Example output

```
🟡 Target: acme-corp-demo.test  —  Severity: MEDIUM
Mode: offline deterministic pipeline, 5 step(s)

Findings (2):
  - [medium] expiring-certificate: TLS certificate for acme-corp-demo.test expires in 19 day(s).
  - [medium] exposed-subdomain: Sensitive-sounding subdomain 'staging.acme-corp-demo.test' resolves publicly to 10.20.4.17.

Tools called:
  - dns_lookup x1
  - subdomain_enum x1
  - http_probe x1
  - tls_probe x1
  - whois_lookup x1

Summary:
[offline deterministic pipeline — set ANTHROPIC_API_KEY for an adaptive agentic run]
Overall severity: MEDIUM.
2 finding(s) identified across DNS, subdomain, HTTP, and TLS checks.
- [medium] TLS certificate for acme-corp-demo.test expires in 19 day(s).
- [medium] Sensitive-sounding subdomain 'staging.acme-corp-demo.test' resolves publicly to 10.20.4.17.
Recommended next steps: review any exposed sensitive subdomains for unintended
public access, add missing security headers, and renew or rotate certificates
flagged as expiring.
```

(Synthetic sample output for illustration — `acme-corp-demo.test` is a
fictitious target, not a real domain. Shape matches a real offline-mode
run against a live target.)

## Project layout

```
recon-agent/
├── recon_agent/
│   ├── net.py        # the only module that touches sockets/HTTP/TLS/WHOIS
│   ├── tools.py       # dns_lookup, subdomain_enum, http_probe, tls_probe, whois_lookup
│   ├── findings.py     # deterministic severity rules over raw tool output
│   ├── agent.py         # the tool-use loop + offline fallback + TOOL_SPECS
│   ├── report.py         # human-readable report rendering
│   └── cli.py              # argparse entry point
├── examples/
└── tests/                    # pytest, fully offline via recon_agent.net monkeypatching
```

## Design notes / limitations

- **Subdomain wordlist is small and built-in** (`www`, `mail`, `api`, `dev`,
  `staging`, `test`, `admin`, `vpn`, `portal`, `ftp`, `internal`) — enough to
  demonstrate the pattern, not a real subdomain enumeration tool. Swap in a
  larger list, or a real source like certificate-transparency logs, for
  production use.
- **`net.py` is the only network boundary.** Every test monkeypatches its
  four functions (`resolve_host`, `http_get_headers`,
  `fetch_tls_certificate`, `whois_query`) rather than mocking the Anthropic
  SDK's transport or hitting real hosts, which is what keeps the suite fast
  and fully offline.
- **Tool failures are data, not crashes.** `ReconAgent._call_tool` catches
  any exception a tool raises (DNS failure, connection refused, TLS
  handshake failure) and stores it as an `{"error": ...}` result, so a
  partially-unreachable target still produces a complete report instead of
  an unhandled traceback — important both for a real recon run and for the
  agent loop, where a failed tool call still needs a `tool_result` to send
  back to the model.
- **WHOIS is best-effort.** `python-whois` is an optional dependency; without
  it, `whois_lookup` returns `{"available": False}` rather than failing.

## Testing

```bash
pytest -q
```

31 tests cover the individual tools (headers, TLS expiry math, subdomain
sensitivity flagging), the findings/severity rules, the agentic loop itself
(via a fake Anthropic client that mimics the SDK's tool-use response shape —
including a multi-round tool-use sequence, a max-steps cutoff, an unknown
tool name, and a live-call failure falling back to offline mode), the
offline pipeline, report rendering, and the CLI (JSON and human output). No
network access or API key is required.
