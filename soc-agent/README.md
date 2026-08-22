# SOC Agent

An autonomous incident-investigation agent: given a raw security incident
(host, user, process, indicators), it decides for itself which tools to call
— threat-intel lookup, process reputation, asset criticality, user baseline
deviation, ATT&CK mapping — gathering evidence step by step and adapting the
plan to what it finds, before producing a severity verdict, recommended
actions, and an analyst-facing narrative.

## Why this exists

The other tools in this repo (`log-triage-assistant`, `ioc-triage-assistant`)
are pipelines: a fixed sequence of stages runs on every input, in the same
order, every time. That's the right shape for extraction/enrichment/scoring,
but it isn't what an "agent" means in the agentic-AI sense.

This project is the agentic-pipeline counterpart: a small, from-scratch
**plan → act → observe** loop (no LangChain/AutoGen/etc.) where each next
step is chosen conditionally from the incident *and* from what earlier tool
calls already turned up:

- It only checks a user's login baseline once it has a host and a user to
  check.
- It only runs the MITRE ATT&CK mapping if something upstream (a malicious
  indicator, a suspicious process, a baseline deviation) actually surfaced
  — otherwise it finishes early rather than running every tool reflexively.
- Two incidents with the same shape but different evidence take genuinely
  different paths through the tool graph. See the two examples below: the
  malicious one runs 6 tool calls, the benign one runs 3 and skips ATT&CK
  entirely.

The default planner (`DeterministicPlanner`) encodes that policy directly in
Python, so the tool is fully runnable and testable with no API key. Passing
`--llm-planner` swaps it for `LLMPlanner`, which asks Claude — via a real
`tool_use` function-calling request — to choose the next tool itself at each
step, falling back to the deterministic policy automatically if no
`ANTHROPIC_API_KEY` is set or the call fails. The agent loop in `agent.py` is
identical either way; only the thing deciding "what's next" changes.

## Architecture

```
Incident (JSON: host, user, process, command line, indicators, description)
        │
        ▼
┌──────────────────────────── InvestigationAgent ────────────────────────────┐
│  loop (max_steps):                                                         │
│    action = planner.decide(state)   ── DeterministicPlanner (default), or  │
│                                          LLMPlanner (Claude tool-use call)  │
│    if action == FINISH: break                                              │
│    result = tools.call(action)      ── threat_intel_lookup                 │
│                                         process_reputation_lookup          │
│                                         asset_criticality_lookup           │
│                                         user_baseline_check                │
│                                         attack_technique_lookup            │
│    state.steps.append(action, result)                                     │
└──────────────────────────────────────────────────────────────────────────-┘
        │
        ▼
score_verdict(state)  ── deterministic severity (low/medium/high/critical)
        │                + recommended actions, from the gathered evidence
        ▼
llm_client.narrate()  ── Claude-written narrative, or a deterministic
                          offline summary template if no API key is set
        │
        ▼
InvestigationReport (human-readable or JSON)
```

Tool selection (agentic) and verdict scoring (deterministic) are deliberately
separate: whichever planner picked the tool calls, the same scoring function
turns the transcript into a severity and action list, so the verdict is
reproducible regardless of planning mode.

## Quickstart

```bash
cd soc-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for live Claude planning/narration
pytest -q

soc-agent --file examples/sample_incident_malicious.json
soc-agent --file examples/sample_incident_benign.json --json
cat examples/sample_incident_malicious.json | soc-agent
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m soc_agent.cli --file examples/sample_incident_malicious.json
```

### Enabling the LLM-driven planner and narrative

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
soc-agent --file examples/sample_incident_malicious.json --llm-planner
```

Without `--llm-planner`, tool selection is always deterministic — but the
narrative step still uses Claude automatically whenever a key is present.
Without a key at all, the CLI reports `Planning: deterministic (offline)` and
`Narrative: offline heuristic fallback` and still produces a complete report.

## Incident format

```json
{
  "incident_id": "INC-2041",
  "hostname": "FIN-SQL01",
  "user": "asingh",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -enc SQBuAHYAbwBrAGUA...",
  "indicators": ["185.220.101.7", "evil-c2-panel.io"],
  "description": "EDR flagged an encoded PowerShell command beaconing out..."
}
```

All fields are optional except `incident_id`; the planner only calls tools
relevant to the fields actually present.

## Project layout

```
soc-agent/
├── soc_agent/
│   ├── models.py       # Incident, ToolCall, ToolStep dataclasses
│   ├── tools.py         # the 5 tools + ToolRegistry (name/schema/handler)
│   ├── planner.py       # DeterministicPlanner + LLMPlanner (ReAct-style)
│   ├── llm_client.py    # Claude tool-use planning call + narrative call
│   ├── agent.py         # the investigation loop + deterministic scoring
│   ├── report.py        # human-readable rendering
│   └── cli.py            # argparse CLI
├── data/
│   ├── threat_intel.json          # synthetic demo threat-intel feed
│   ├── asset_inventory.json        # synthetic demo asset criticality/owner
│   ├── user_baselines.json         # synthetic demo per-user host baselines
│   └── attack_techniques.json      # curated ATT&CK subset w/ match keywords
├── examples/
│   ├── sample_incident_malicious.json
│   └── sample_incident_benign.json
└── tests/                          # pytest, fully offline
```

## Design notes / limitations

- **All local datasets are synthetic**, sized for a clear demo rather than
  production coverage. `tools.py`'s `_load_json` calls are the seam to swap
  in a real EDR/SIEM API, CMDB, or IdP for live baseline data.
- **ATT&CK mapping is keyword-based, not retrieval-based.** `ioc-triage-assistant`
  already demonstrates a from-scratch TF-IDF/RAG index over ATT&CK; this
  project's contribution is the tool-calling agent loop, so its ATT&CK tool
  stays intentionally simple (explicit keyword lists per technique).
- **`max_steps` is a hard safety cap** (default 8), not a tuning knob — a
  real agent loop needs a termination guarantee independent of the planner's
  own judgment.
- **The LLM planner is a single tool-use call per step**, invoked repeatedly
  by the same outer loop the deterministic planner uses — there's no hidden
  multi-turn conversation state inside `LLMPlanner`; `agent.py` is the only
  place the loop actually lives.

## Testing

```bash
pytest -q
```

35 tests cover the individual tools, the deterministic planner's conditional
branching (including early termination and the fixed tool ordering), the
end-to-end agent loop on both a malicious and a benign incident, deterministic
severity scoring, the offline LLM fallbacks for both planning and narration
(including a mocked Claude tool-use response), and the CLI itself as a
subprocess. No network access or API key is required to run the suite.
