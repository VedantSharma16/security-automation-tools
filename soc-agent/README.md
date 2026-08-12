# SOC Agent

An agentic SOC alert-triage assistant. Give it a raw security alert and it
investigates it autonomously — deciding which tools to call, in what order,
based on what it learns — then submits a structured verdict with a
reasoning trace an analyst can audit.

This is a companion to [`ioc-triage-assistant/`](../ioc-triage-assistant/)
in this repo, and deliberately a different shape of pipeline:
`ioc-triage-assistant` is a **fixed pipeline** (extract → enrich → retrieve →
summarize, always in that order). `soc-agent` is a **genuine agent loop** —
when a live LLM is available, the model itself chooses which tool to call
next and when it has enough evidence to conclude, rather than following a
hardcoded sequence.

## Why this exists

"Agentic pipeline" is often used loosely to mean "an LLM call in a script."
This project implements the real mechanics of a tool-calling agent loop —
the pattern behind Claude's tool use / the Claude Agent SDK — with nothing
hidden behind a framework:

- **A real control loop.** The agent sends the alert plus a set of tool
  schemas to Claude, executes whatever tool(s) the model calls, feeds the
  results back as `tool_result` blocks, and repeats until the model calls a
  dedicated `submit_verdict` tool (or exhausts its step budget). See
  `soc_agent/agent.py:_investigate_live`.
- **The model chooses the investigation path.** Given a phishing alert vs. a
  C2-beacon alert, the tools called — and their order — differ, because the
  model is reasoning about what to check next, not executing a script.
- **Fully offline-testable.** Without `ANTHROPIC_API_KEY`,
  `soc_agent/planner.py` runs a deterministic, rule-based investigation
  using the exact same tool functions, producing a trace in the same shape.
  This keeps the CLI and full test suite runnable with no network access or
  API key — the same design used by `ioc-triage-assistant` and
  `log-triage-assistant` elsewhere in this repo.
- **Tools are the seam to real systems.** `ioc_lookup`, `dns_lookup`,
  `mitre_lookup`, `search_logs`, and `get_asset_criticality` each read a
  small local JSON dataset under `data/`, standing in for a TIP, DNS/WHOIS,
  a curated ATT&CK reference, a SIEM, and a CMDB respectively.

## How the agent loop works

```
Alert
  │
  ▼
SocAgent.investigate()
  │
  ├─ live mode (ANTHROPIC_API_KEY set) ───────────────────────────┐
  │    loop (until submit_verdict or max_steps):                  │
  │      1. send alert + conversation so far + tool schemas       │
  │      2. Claude replies with tool_use block(s)                 │
  │      3. execute each tool against local data/                 │
  │      4. append tool_result(s) to the conversation             │
  │      5. Claude either calls another tool or submit_verdict     │
  │    → AgentResult(trace, verdict, mode="live")                 │
  │                                                                 │
  └─ offline mode (no key) ───────────────────────────────────────┘
       planner.run(): scripted investigation using the same tools
       → AgentResult(trace, verdict, mode="offline")
```

Both paths return the same `AgentResult`: a step-by-step trace of every
tool call and its output, plus a `Verdict` (`malicious` / `suspicious` /
`benign` / `inconclusive`, a confidence score, a recommended action, and a
rationale).

## Quickstart

```bash
cd soc-agent
pip install -e ".[dev]"       # add ".[dev,llm]" for the live tool-calling agent
pytest -q

soc-agent --file examples/alert_cnc_beacon.json
soc-agent --file examples/alert_phishing_credential.json --json
cat examples/alert_benign_login.json | soc-agent
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m soc_agent.cli --file examples/alert_cnc_beacon.json
```

### Enabling the live agent

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
soc-agent --file examples/alert_cnc_beacon.json
```

Without a key, the CLI prints `LLM-backed: no (offline deterministic
planner...)` and still runs a complete, multi-step investigation — the
offline planner is a real (if scripted) investigation, not a placeholder.

## Example output

```
🔴 Verdict: MALICIOUS (confidence=0.95)
Mode: offline

Rationale: 2 indicator(s) matched known-malicious threat intel;
newly-registered/privacy-proxied domain(s) involved (update-service-cdn.net);
behavior corroborated by ATT&CK technique(s) T1071.001; 4 corroborating log
line(s) found.
Recommended action: Isolate the affected host, block the indicators at the
perimeter, and open a full incident.

Investigation trace (7 step(s)):
  1. ioc_lookup(indicator='update-service-cdn.net')
       -> {"indicator": "update-service-cdn.net", "found": true, "type": "domain", "verdict": "malicious", ...}
  2. ioc_lookup(indicator='185.220.101.1')
       -> {"indicator": "185.220.101.1", "found": true, "type": "ip", "verdict": "malicious", ...}
  3. ioc_lookup(indicator='10.20.4.17')
       -> {"indicator": "10.20.4.17", "found": false, "verdict": "unknown", ...}
  4. dns_lookup(domain='update-service-cdn.net')
       -> {"domain": "update-service-cdn.net", "found": true, "age_days": 13, "registrar": "NameCheap (privacy-proxied)", ...}
  5. mitre_lookup(keyword='beacon')
       -> {"keyword": "beacon", "matches": [{"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", ...}]}
  6. search_logs(query='10.20.4.17')
       -> {"query": "10.20.4.17", "match_count": 4, ...}
  7. get_asset_criticality(hostname='WKS-DEV-14')
       -> {"hostname": "WKS-DEV-14", "found": true, "criticality": "medium", ...}
```

## Project layout

```
soc-agent/
├── soc_agent/
│   ├── agent.py     # live tool-calling loop + fallback dispatch
│   ├── planner.py   # deterministic offline investigation (same tools)
│   ├── tools.py     # tool implementations + Anthropic tool-use schemas
│   ├── models.py    # Alert / AgentStep / Verdict / AgentResult dataclasses
│   └── cli.py       # argparse CLI
├── data/
│   ├── threat_intel.json        # synthetic IOC feed
│   ├── mitre_techniques.json    # curated ATT&CK technique subset
│   ├── dns_records.json         # mock DNS/registration resolver
│   ├── asset_inventory.json     # mock CMDB
│   └── sample_logs/auth.log     # log corpus for search_logs
├── examples/                    # a beacon, a phishing, and a benign alert
└── tests/                       # pytest, fully offline
```

## Design notes / limitations

- **All local datasets are synthetic**, sized for a clear demo, not
  production threat intelligence. Each `tools.py` function is the seam to
  swap in a real TIP (MISP, OTX), a real DNS/WHOIS API, a real SIEM query,
  and a real CMDB.
- **The offline planner is intentionally simple and rule-based.** It exists
  so the project has zero required external dependencies and a fully
  deterministic test suite — it is not meant to replicate an LLM's
  reasoning, only to exercise the same tools end-to-end.
- **`max_steps` is a hard safety cap** on both paths. In live mode, an
  agent that never calls `submit_verdict` returns an explicit
  `inconclusive` verdict for human escalation rather than looping forever.
- **Domain extraction uses a small TLD allowlist** (same trick as
  `ioc-triage-assistant`) to avoid treating filenames (`explorer.exe`) or
  dotted usernames (`j.morales`) as domains.

## Testing

```bash
pytest -q
```

28 tests cover the individual tools, the offline planner's investigation
and scoring logic, the live agent's tool-calling control flow (via a
scripted fake Anthropic client — no network or API key needed), and the
CLI end-to-end as a subprocess on both human-readable and JSON output.
