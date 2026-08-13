# recon-agent

An agentic recon tool: instead of running a fixed pipeline, a *planner*
decides — one step at a time, based on what's been discovered so far —
which read-only recon tool to call next against an authorized target. It
scans a curated set of common ports, fingerprints whatever's listening,
pulls TLS certificate details on HTTPS ports, checks each fingerprinted
service/version against a local CVE knowledge base, and produces a
pentest-style recon report with the full decision trace attached.

The planner is swappable: a fully offline `DeterministicPlanner` drives the
CLI by default, and an `LLMPlanner` hands the same five tools to Claude via
native tool-use and lets the model make each decision itself when
`ANTHROPIC_API_KEY` is set. Both speak the same `Action`/`Observation`
protocol, so the run loop doesn't know or care which one is driving.

## Why this exists

The rest of this repo's tooling ([`log-triage-assistant/`](../log-triage-assistant/),
[`ioc-triage-assistant/`](../ioc-triage-assistant/), [`process_threat_hunter/`](../process_threat_hunter/))
is blue-team/IR: parsing logs, triaging alerts, hunting processes. This one
is deliberately the other half — a small, safe demonstration of offensive
recon — and it's also the first project here where an LLM is genuinely
**agentic**: choosing its own next action from a tool menu and the current
state, rather than filling in a fixed template (RAG retrieval) or following
a rule engine (detection rules). That loop — bind a handful of tools,
give an LLM the current state, let it pick the next call, feed the result
back, repeat until done — is the same shape used by real agentic security
tooling (autonomous recon agents, SOC copilots with tool access), just
scoped down to something safe to run and easy to read end to end.

## Safety model

This is a **read-only fingerprinting tool**, not an exploitation
framework — no exploit code, no brute forcing, no full 65535-port sweeps.
Two guardrails are load-bearing, not decorative:

- **Authorization gating** (`recon_agent/safety.py`): private/loopback
  targets (`127.0.0.1`, `10.x`, `192.168.x`, `localhost`, ...) are always
  allowed, since you're almost certainly testing your own lab. Anything
  else is refused unless you pass `--authorized` on the CLI, confirming you
  have explicit permission. This check runs before a single packet is sent.
- **Curated port list, not a sweep** (`recon_agent/tools.py:TOP_PORTS`): the
  scanner checks ~15 well-known ports by default, not the full range. This
  is a fingerprinting demo, not a stealth scanner.

Only run this against systems you own or are explicitly authorized to test.

## Architecture

```
                     ┌──────────────────────────┐
                     │   Action / Observation    │
                     │        protocol           │
                     └────────────┬───────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                          │                          │
DeterministicPlanner        LLMPlanner              (run loop in agent.py)
 rule-based state           Claude native tool-use    executes the chosen
 machine — same 5           picks the next tool        tool, updates RunState,
 tools, offline,            call itself, one step       hands the result back
 deterministic order        at a time                    to the planner
        │                          │                          │
        └─────────────┬────────────┘                          │
                       ▼                                       │
              recon_agent/tools.py  ◄───────────────────────────┘
       tcp_connect_scan · grab_banner · http_headers · tls_cert_info
                       │
                       ▼
              recon_agent/vuln_kb.py
       local CVE lookup by fingerprinted service + version
                       │
                       ▼
              recon_agent/report.py
        console / Markdown / JSON report + full decision trace
```

The five tools the planner can call: `tcp_connect_scan`, `grab_banner`,
`http_headers`, `tls_cert_info`, and `vuln_lookup` (against the local KB).
A sixth, `finish`, is how the LLM planner signals it's done; the
deterministic planner signals the same thing by returning `None`.

## Quickstart

```bash
cd recon-agent
pip install -e ".[dev]"        # add ".[llm]" for the Claude planner + narrative, ".[tls]" for full cert parsing
pytest -q

# Scan your own machine (loopback is always authorized)
recon-agent --target 127.0.0.1

# A specific port list, and write both report formats
recon-agent --target 127.0.0.1 --ports 22,80,443 --json-out report.json --md-out report.md

# A non-private target requires an explicit authorization confirmation
recon-agent --target example.com --authorized
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m recon_agent.cli --target 127.0.0.1
```

### Enabling the LLM planner

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
recon-agent --target 127.0.0.1 --use-llm
```

Without a key, `--use-llm` prints a warning and falls back to the
deterministic planner — the tool always finishes a run and produces a
complete report either way.

## Example output

Running against a machine with an SSH server and an outdated nginx exposed:

```
recon-agent — target 10.0.0.42
Overall risk      : HIGH
Steps taken       : 6 (completed)
Open ports        : 22, 443

Fingerprints:
  port 22    OpenSSH 7.2 (via banner)
  port 443   nginx 1.4.0 (via http)

TLS certificates:
  port 443   TLSv1.2 subject=CN=10.0.0.42, expires in 214d

Potential known vulnerabilities:
  [MEDIUM  ] CVE-2016-6210 — port 22 OpenSSH 7.2
             OpenSSH 7.2 has a timing side-channel in password authentication that allows remote username enumeration.
  [HIGH    ] CVE-2013-2028 — port 443 nginx 1.4.0
             nginx chunked transfer-encoding handling has a stack buffer overflow that can lead to remote code execution.

Summary:
  [offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis] Overall risk: HIGH. 2 open port(s)
  discovered on 10.0.0.42. Potential known-vulnerability matches: CVE-2013-2028, CVE-2016-6210. Verify manually
  before reporting to a client. Recommended next steps: manually verify each finding, check authentication on any
  exposed database/management ports, and confirm patch levels against vendor advisories before escalating.
```

The Markdown/JSON reports additionally include the full agent transcript —
every tool call the planner made, in order, with its stated reason — so a
reviewer can see exactly how the agent got to its conclusions, not just the
conclusions themselves.

## Project layout

```
recon-agent/
├── recon_agent/
│   ├── tools.py        # tcp_connect_scan, grab_banner, http_headers, tls_cert_info
│   ├── vuln_kb.py       # offline CVE lookup by service/version
│   ├── safety.py        # target-authorization guardrails
│   ├── agent.py          # Action/Observation loop + DeterministicPlanner
│   ├── llm_client.py     # LLMPlanner (Claude tool-use) + narrative generation
│   ├── report.py         # console / Markdown / JSON rendering
│   └── cli.py             # argparse CLI
├── data/
│   └── known_service_vulnerabilities.json  # curated, public CVE reference data
├── tests/                 # pytest, fully offline (local TCP/TLS test servers, mocked LLM client)
└── examples/
```

## Design notes / limitations

- **The CVE knowledge base is small and curated**, covering a handful of
  historically significant, widely-taught vulnerabilities (the vsftpd 2.3.4
  backdoor, ProFTPD's mod_copy backdoor, the Apache path-traversal pair,
  etc.) for demo purposes — it is informational only, with no exploit code.
  `vuln_kb.VulnKnowledgeBase` is the seam to point at a real feed (NVD API,
  an internal CVE database) for production use.
- **TLS certificate field parsing is optional.** Protocol and cipher are
  always reported; subject/issuer/expiry require the `cryptography` package
  (`pip install .[tls]`) — without it those fields report as unavailable
  rather than being guessed at.
- **Banner/header service-version parsing is regex-based and best-effort**,
  same as any passive fingerprinting tool — some services won't be
  identified, and that's reported honestly (`service: null`) rather than
  papered over.
- **The deterministic planner's order is fixed** (scan → fingerprint every
  port → TLS on HTTPS ports → vuln lookup → finish); the LLM planner can, in
  principle, deviate from that order based on what it observes, which is
  the whole point of giving it the tools directly instead of hardcoding a
  pipeline.

## Testing

```bash
pytest -q
```

53 tests cover the recon primitives (against real local TCP/TLS servers
spun up in-process, not mocked sockets), the vulnerability knowledge base,
authorization gating, the deterministic planner and full agent run loop,
the LLM planner (with a scripted fake Anthropic client — no API key or
network access needed), report rendering, and the CLI end to end. No
external network access or API key is required to run the suite.
