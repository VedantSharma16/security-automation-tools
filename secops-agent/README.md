# SecOps Agent

A small, sandboxed **tool-using agent** for SOC alert investigation. Give it
a natural-language question — *"investigate repeated failed logins on
db-prod-01 from 203.0.113.77, possible T1110"* — and it autonomously decides
which of four read-only tools to call, in what order, using what it learns
from one call to decide the next, until it has enough evidence to hand back
a verdict and a report.

It's the "agentic pipeline" counterpart to this repo's other two AI-security
projects: [`ioc-triage-assistant/`](../ioc-triage-assistant/) is retrieval
(RAG) over a fixed pipeline, and [`log-triage-assistant/`](../log-triage-assistant/)
is deterministic detection plus an LLM narrative step. This project is the
one where the model itself drives the control flow — deciding *which* tools
to call and *when* it's done — which is what makes it agentic rather than a
fixed sequence of stages.

## Why this exists

"Agentic" gets used loosely. Concretely, this project demonstrates:

- **A real multi-turn tool-use loop** against the Claude API (`planner.py`,
  `AnthropicPlanner`): the model receives tool schemas, chooses to call one
  or several in parallel, receives their results, and decides whether to
  call more tools or answer — the textbook plan → act → observe cycle, not
  a single one-shot function call.
- **Guardrails a real agent needs**, not just a happy-path demo:
  - *Tool allowlist* — the agent can only ever invoke the four tools defined
    in `tools.py`; anything else raises `ToolError`.
  - *Sandboxed log access* — `search_logs` cannot accept an arbitrary path
    from the model. The log file is bound once when the investigation
    starts, so a prompt-injected or misbehaving model can't redirect the
    agent to read files outside what the analyst approved.
  - *Iteration budget* — `max_iterations` forces the loop to stop and hand
    off to a human rather than looping forever if the model never converges
    on a final answer.
  - *No side effects* — every tool is a read-only local lookup. There is no
    live network I/O, no filesystem write, no shell execution reachable
    from the agent.
- **A fully offline, deterministic mode** (`OfflinePlanner`) that needs no
  API key: it extracts entities (IPs, hostnames, ATT&CK IDs) from the query
  and from tool observations with regexes, and walks a fixed investigation
  checklist. This is what the test suite and the CLI run by default, so the
  tool — and its tests — work with zero network access.

## How the loop works

```
 investigate(query)
        │
        ▼
 ┌─────────────────────────────┐
 │ planner.decide(state)        │  ← "what should I do next, given
 └─────────────┬────────────────┘     the query and everything observed
               │                       so far?"
     tool_call │  final
               ▼
 ┌─────────────────────────────┐
 │ tools.execute(name, args)    │  ← allowlisted, sandboxed, never raises
 └─────────────┬────────────────┘     out of the loop
               │
               ▼
 ┌─────────────────────────────┐
 │ planner.observe(action, out) │  ← stateful planners (AnthropicPlanner)
 └─────────────┬────────────────┘     fold the result back into context
               │
               └──── loop, up to max_iterations ────┐
                                                       │
                              stop → verdict + report ◄┘
```

Two tools available to the agent are pure local lookups
(`lookup_ioc`, `lookup_mitre_technique`, `check_asset_criticality`) against
small JSON datasets in `data/`; `search_logs` greps the one log file bound
to the investigation and also returns any IPv4 addresses it finds in the
matching lines — which is what lets the agent pivot from "here's a log hit"
to "let me check that IP against threat intel" on its own, whichever
planner is driving.

## Quickstart

```bash
cd secops-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live Claude planner
pytest -q

secops-agent investigate \
  --query "Investigate repeated failed logins on db-prod-01 from 203.0.113.77, possible T1110" \
  --log examples/sample_investigation.log
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m secops_agent.cli investigate --query "..." --log examples/sample_investigation.log
```

### Enabling the live agentic planner

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
secops-agent investigate --query "..." --log examples/sample_investigation.log --llm
```

Without `--llm` (the default), `OfflinePlanner` drives the investigation
deterministically — no key, no network, fully reproducible. With `--llm`,
`AnthropicPlanner` runs the real tool-use loop and the model itself chooses
the tool sequence.

### Exit codes

`secops-agent investigate` exits `2` when the verdict is a `malicious*`
verdict (useful for scripting/CI gating), `1` on a usage error (e.g. a
missing `--log` file), and `0` otherwise.

## Example output

```
$ secops-agent investigate --query "Investigate repeated failed logins on db-prod-01 from 203.0.113.77, possible T1110" --log examples/sample_investigation.log

Trace:
  1. search_logs({'pattern': '203.0.113.77'}) -> [ok] {'searched': True, 'match_count': 5, 'extracted_ips': ['203.0.113.77'], ...}
  2. lookup_ioc({'indicator': '203.0.113.77'}) -> [ok] {'is_known_malicious': True, 'confidence': 'medium', ...}
  3. check_asset_criticality({'hostname': 'db-prod-01'}) -> [ok] {'found': True, 'criticality': 'critical', ...}
  4. lookup_mitre_technique({'technique_id': 'T1110'}) -> [ok] {'found': True, 'name': 'Brute Force', ...}

Verdict: malicious (critical asset in scope)

Report:
Log search for '203.0.113.77' found 5 matching line(s). KNOWN MALICIOUS indicators:
203.0.113.77 (medium confidence). Asset db-prod-01: criticality=critical, ...
Recommended next steps: contain/isolate any host communicating with the flagged
indicator(s), pivot on those indicators across EDR/SIEM for related activity, ...
```

## Project layout

```
secops-agent/
├── secops_agent/
│   ├── tools.py     # tool schemas + ToolRegistry (allowlist, log-path sandbox)
│   ├── state.py     # InvestigationState / ToolCallRecord shared across the loop
│   ├── planner.py   # OfflinePlanner (deterministic) + AnthropicPlanner (live tool-use loop)
│   ├── agent.py      # SecOpsAgent: the plan → act → observe orchestration loop
│   └── cli.py        # argparse CLI
├── data/
│   ├── threat_intel.json          # synthetic demo IOC feed
│   ├── mitre_attack_techniques.json
│   └── asset_inventory.json       # synthetic demo CMDB
├── examples/sample_investigation.log
└── tests/            # pytest, fully offline — including a scripted fake
                        # Anthropic client that exercises the live tool-use
                        # loop's message bookkeeping without any API key
```

## Design notes / limitations

- **Datasets are synthetic**, in the same spirit as `ioc-triage-assistant`.
  `data/threat_intel.json`, `data/mitre_attack_techniques.json`, and
  `data/asset_inventory.json` are small illustrative demo datasets, not live
  intelligence or a real CMDB — `tools.py` is the seam to swap in real
  sources (MISP/OTX/an internal blocklist; a live CMDB API).
- **`OfflinePlanner`'s entity extraction is intentionally simple regexes**
  (IPv4, `T\d{4}`, hyphenated hostnames). It's there to make the agent loop
  itself deterministic and testable, not to be a general NLU layer — the
  live `AnthropicPlanner` is where genuine language understanding of the
  query comes from.
- **The verdict is a coarse heuristic** (`agent.derive_verdict`), not a
  substitute for analyst judgment: it only ever says "malicious" when a
  `lookup_ioc` call actually returned a known-malicious hit, and otherwise
  reports "suspicious", "inconclusive", or "no evidence gathered" rather
  than guessing "benign" from absence of evidence.

## Testing

```bash
pytest -q
```

24 tests cover the tool registry (including the allowlist and the log-path
sandbox), the offline planner end-to-end through `SecOpsAgent`, the
iteration-budget guardrail, the live tool-use loop's message bookkeeping
(via a scripted fake Anthropic client — including parallel tool calls
batched into a single `tool_result` turn), and the CLI as a subprocess. No
network access or API key is required to run the suite.
