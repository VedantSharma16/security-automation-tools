# SOC Alert Triage Agent

An autonomous, tool-calling agent that triages SOC alerts the way a real
AI-assisted analyst copilot would: given one alert, it decides for itself
which investigative tools to call — indicator reputation, asset
criticality, alert correlation, MITRE ATT&CK context — gathers evidence
across as many steps as it needs, and then calls a terminal tool
(`escalate` / `monitor` / `close`) with a reason grounded in what it
actually observed. Every step is recorded, so the output is a full,
inspectable audit trail, not just a final label.

## Why this is different from the other tools in this repo

`ioc-triage-assistant` and `log-triage-assistant` are **fixed pipelines**:
extract → enrich → retrieve → summarize, always in that order, once. This
project is a genuine **agentic loop**: the model (or, offline, a
deterministic planner standing in for it) chooses which tool to call next,
observes the result, and decides whether it has enough evidence to stop —
using the Anthropic Messages API's native tool use, the same mechanism
production LLM agents use to take action in the real world.

It's built to demonstrate that pattern specifically, alongside the
detection-engineering fundamentals the rest of the repo covers: bounded,
auditable autonomy over a fixed toolbox, rather than an LLM that outputs
free-form prose triage.

## Agent loop

```
             ┌────────────────────────────────────────────┐
             │              alert (JSON)                   │
             └───────────────────────┬──────────────────────┘
                                      ▼
                     ┌────────────────────────────┐
                     │   agent decides next step    │◄────────┐
                     │  (LLM tool-use, or planner)   │         │
                     └───────────────┬────────────┘         │
                                      ▼                        │
     ┌──────────────────────────────────────────────────┐    │
     │ lookup_ioc_reputation │ get_asset_criticality      │    │
     │ search_attack_technique │ check_related_alerts     │────┘
     └──────────────────────────────────────────────────┘
                                      │  (repeat until enough evidence)
                                      ▼
                    escalate(reason) │ monitor(reason) │ close(reason)
                                      ▼
                          AgentResult: verdict + full step trace
```

Two interchangeable backends drive the same loop:

- **`soc_agent/llm_agent.py`** — a real ReAct-style loop against the
  Anthropic Messages API's tool-use feature. The model sees the alert,
  calls tools, sees their results, and keeps going until it calls a
  terminal tool or a step budget is hit.
- **`soc_agent/planner.py`** — a deterministic, offline stand-in: it calls
  every tool in a fixed sensible order and scores the evidence with a
  transparent point system (indicator reputation × asset criticality ×
  campaign correlation × ATT&CK relevance). This is what runs by default,
  what the test suite runs against, and what the LLM backend falls back to
  if no API key is set or the API call fails — the same offline-fallback
  contract the rest of this repo's tools follow.

Both backends dispatch through the exact same `ToolRegistry`, so their
outputs — a list of `AgentStep`s and a final verdict — are directly
comparable.

## Quickstart

```bash
cd soc-alert-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live agentic loop
pytest -q

soc-agent --queue examples/sample_alerts.json
soc-agent --queue examples/sample_alerts.json --alert-id ALT-1001
soc-agent --queue examples/sample_alerts.json --json
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m soc_agent.cli --queue examples/sample_alerts.json
```

### Enabling the live agentic loop

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
soc-agent --queue examples/sample_alerts.json --alert-id ALT-1001 --llm
```

Without a key (or without `--llm` at all), the CLI reports
`Backend: deterministic` and still produces a complete, evidence-grounded
verdict — the deterministic planner is a full implementation of the same
loop, not a placeholder.

## Example: the sample queue

`examples/sample_alerts.json` ships four alerts chosen to exercise all
three verdict tiers under the deterministic planner:

| Alert | Scenario | Verdict |
|---|---|---|
| `ALT-1001` | Encoded PowerShell beaconing to a known-malicious C2 IP, on a crown-jewel production host | 🔴 **escalate** |
| `ALT-1002` | A large outbound transfer to the same C2 IP shortly after — correlated with `ALT-1001` | 🔴 **escalate** |
| `ALT-1003` | A single port-scan probe from an internal, unlisted IP against a low-criticality printer | 🟢 **close** |
| `ALT-1004` | Brute-force-shaped login pattern that succeeds, but from an allowlisted corporate VPN egress IP | 🟡 **monitor** |

`ALT-1004` is the interesting case: the login pattern matches ATT&CK
T1110 (Brute Force) and lands on a higher-criticality asset, but the
source IP is explicitly known-benign in the threat-intel feed — not
enough corroborating evidence to escalate, but not clearly benign enough
to close outright either. That's the kind of judgment call this project
is trying to make legible, not hide behind a single confidence score.

Run `soc-agent --queue examples/sample_alerts.json --alert-id ALT-1001`
to see the full step-by-step trace behind a verdict.

## Project layout

```
soc-alert-agent/
├── soc_agent/
│   ├── models.py      # Alert / AgentStep / AgentResult dataclasses
│   ├── tools.py        # the investigative toolbox + Anthropic tool schemas
│   ├── planner.py       # deterministic offline agent loop (default backend)
│   ├── llm_agent.py     # Anthropic tool-use agentic loop (--llm)
│   ├── agent.py          # picks a backend, with fallback on failure
│   ├── report.py         # human-readable transcript + JSON rendering
│   └── cli.py              # argparse CLI
├── data/
│   ├── threat_intel.json        # synthetic demo threat-intel feed
│   ├── asset_inventory.json      # synthetic demo CMDB / asset inventory
│   └── attack_techniques.json     # curated ATT&CK technique subset (keyword-indexed)
├── examples/sample_alerts.json
└── tests/                          # pytest, fully offline (LLM loop tested via a fake `anthropic` module)
```

## Design notes / limitations

- **All datasets are synthetic demo data**, not live intelligence, CMDB,
  or ATT&CK feeds — see the seams in `tools.py` (`ToolRegistry.__init__`)
  to swap in real sources (a SIEM/EDR API, a real CMDB, MISP/OTX, the
  official ATT&CK STIX bundle).
- **`search_attack_technique` is keyword-overlap, not embedding-based
  retrieval.** `ioc-triage-assistant` already demonstrates a from-scratch
  TF-IDF/cosine RAG index; this project intentionally uses a simpler,
  fully inspectable matcher so the interesting part — the tool-calling
  agent loop itself — stays the focus.
- **The agent's tool budget is bounded (`--max-steps`, default 8)** and it
  fails safe: if the model exhausts its step budget or stops without
  calling a terminal tool, the result defaults to `monitor` rather than
  silently guessing `close`.
- **Every terminal verdict must carry a reason string**, and the
  deterministic planner's reason is built directly from the evidence it
  gathered — never invented — the same "ground the narrative in structured
  evidence" principle `log-triage-assistant` uses for its LLM summaries.

## Testing

```bash
pytest -q
```

30 tests cover every tool in isolation, the deterministic planner's
verdict tiers against all four sample alerts, the LLM agentic loop's
tool-dispatch and stopping conditions (via a fake `anthropic` module — no
network access or API key required), report rendering, and the CLI itself
as a subprocess.
