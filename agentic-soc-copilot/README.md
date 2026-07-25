# Agentic SOC Copilot

An autonomous SOC triage agent that investigates a raw security alert by
**deciding for itself** which tools to call and in what order — checking
indicators against threat intel, checking processes against known
Living-Off-the-Land Binaries (LOLBins), retrieving relevant MITRE ATT&CK
techniques, and weighing the affected asset's business criticality — before
concluding with a structured, schema-validated verdict.

## Why this is different from the other triage tools in this repo

[`ioc-triage-assistant/`](../ioc-triage-assistant/) and
[`log-triage-assistant/`](../log-triage-assistant/) are **linear pipelines**:
extract → enrich → retrieve → summarize, with a single LLM call at the very
end to narrate a result that was already fully computed by deterministic
code. That's a legitimate and common architecture, but it isn't *agentic* —
the model never chooses what to do next.

This project implements a genuine **tool-calling agent loop** using
Anthropic's native tool-use (function-calling) API:

- The model is handed a set of tools and an open-ended instruction
  ("investigate this alert"), not a fixed sequence of steps.
- It decides which tool to call, observes the structured result, and
  decides its *next* move based on that observation — a ReAct-style
  thought → action → observation loop, bounded by a step budget so it can't
  run away.
- It terminates by calling a `submit_verdict` tool with a JSON-schema-enforced
  shape (`verdict`, `confidence`, `reasoning`, `recommended_actions`) instead
  of emitting free text that would need fragile parsing.
- Every step is recorded into an `AgentTranscript` — the full evidence trail
  is returned alongside the verdict, not just the final answer, because an
  automated triage decision that can't be audited isn't usable in a real IR
  workflow.

Like its siblings, it works fully offline: without `ANTHROPIC_API_KEY`, a
deterministic `OfflineAgent` extracts the same categories of entities with
regexes and calls the exact same tools in a fixed order, producing the same
`AgentTranscript` shape — so the rest of the system (and the test suite)
never has to know or care which planner actually ran.

## Architecture

```
alert text
     │
     ▼
 SocAgent.investigate()                      (agent.py — picks a backend)
     │
     ├── live path ──▶ LLMAgent                       (llm_agent.py)
     │                   loop:
     │                     Claude picks a tool ──▶ ToolRegistry.<tool>()
     │                     observation fed back to Claude
     │                     ... until Claude calls submit_verdict
     │
     └── offline path ─▶ OfflineAgent                 (offline_agent.py)
                           regex-extract IOCs / processes / hostname
                           call the same ToolRegistry methods, fixed order
                           rule-based verdict scoring

           ToolRegistry (tools.py)
             ├── lookup_ioc            → data/threat_intel.json
             ├── check_process         → data/lolbins.json
             ├── lookup_attack_technique → data/attack_techniques.json  (keyword-overlap retrieval)
             └── get_asset_criticality → data/asset_inventory.json

     ▼
 AgentTranscript { steps: [thought, tool, tool_input, observation], verdict }
```

## Quickstart

```bash
cd agentic-soc-copilot
pip install -e ".[dev]"        # add ".[dev,llm]" for the live Claude agent
pytest -q

soc-agent --file examples/sample_alert.txt
soc-agent --file examples/sample_alert.txt --json
cat examples/sample_alert.txt | soc-agent
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m agentic_soc.cli --file examples/sample_alert.txt
```

### Enabling the live tool-calling agent

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
soc-agent --file examples/sample_alert.txt
```

Without a key, the CLI prints `Agent backend: offline deterministic planner`
and still produces a complete, auditable investigation.

## Example output

Running against `examples/sample_alert.txt` (encoded PowerShell, a scheduled
task for persistence, and beaconing to a known-malicious IP/domain from a
finance-team workstation):

```
Agent backend: offline deterministic planner
Steps taken: 7

Investigation trace:
  1. Checking indicator 91.203.145.12 against local threat intel.
     -> lookup_ioc({'indicator': '91.203.145.12'})
     <- matched: true, confidence: high, "Bulletproof-hosting IP previously observed serving second-stage payloads."
  2. Checking indicator secure-billing-portal.net against local threat intel.
     -> lookup_ioc({'indicator': 'secure-billing-portal.net'})
     <- matched: true, confidence: high, "Lookalike domain impersonating a finance SaaS vendor..."
  3. Checking process explorer.exe against known LOLBins.
     -> check_process({'process_name': 'explorer.exe'})
     <- known_lolbin: false
  4. Checking process powershell.exe against known LOLBins.
     -> check_process({'process_name': 'powershell.exe'})
     <- known_lolbin: true, risk_level: high, technique_id: T1059.001
  5. Checking process schtasks.exe against known LOLBins.
     -> check_process({'process_name': 'schtasks.exe'})
     <- known_lolbin: true, risk_level: medium, technique_id: T1053.005
  6. Looking up business criticality of host WKSTN-FIN-017.
     -> get_asset_criticality({'hostname': 'WKSTN-FIN-017'})
     <- criticality: high, role: workstation, "frequent phishing target"
  7. Retrieving MITRE ATT&CK techniques matching the alert narrative.
     -> lookup_attack_technique({'query': '...', 'top_k': 2})
     <- T1053.005 Scheduled Task (relevance=0.33), T1071.001 Application Layer Protocol (relevance=0.20)

🔴 Verdict: MALICIOUS (confidence=0.90)

Reasoning:
  High-confidence known-malicious indicator(s) matched local threat intel: 91.203.145.12,
  secure-billing-portal.net. High-risk LOLBin(s) observed: powershell.exe. Affected host
  WKSTN-FIN-017 has business criticality 'high'. Alert narrative closely matches a known
  ATT&CK technique (see retrieved matches).

Recommended actions:
  - Isolate the affected host from the network immediately.
  - Escalate to incident response / the on-call lead.
  - Pivot on the confirmed indicators across EDR/SIEM for related activity.
  - Preserve forensic evidence (memory and disk image) before remediation.
```

## Project layout

```
agentic-soc-copilot/
├── agentic_soc/
│   ├── tools.py           # ToolRegistry: 4 tools over local reference data
│   ├── llm_agent.py       # live Anthropic tool-use loop + submit_verdict
│   ├── offline_agent.py   # deterministic regex-extract + fixed-order planner
│   ├── agent.py           # SocAgent facade: live-with-offline-fallback
│   ├── transcript.py      # AgentStep / Verdict / AgentTranscript data model
│   └── cli.py             # argparse CLI
├── data/
│   ├── threat_intel.json          # synthetic demo threat-intel feed
│   ├── lolbins.json               # known Living-Off-the-Land Binaries
│   ├── attack_techniques.json     # curated ATT&CK technique subset
│   └── asset_inventory.json       # hostname → business criticality
├── examples/sample_alert.txt
└── tests/                          # pytest, fully offline (incl. a mocked
                                     # Anthropic client to unit-test the
                                     # live tool-calling loop without network)
```

## Design notes / limitations

- **All reference datasets are synthetic**, sized for a readable demo, not
  production coverage. `ToolRegistry.from_files()` is the seam to swap in a
  real threat-intel feed, EDR telemetry, the full MITRE ATT&CK STIX bundle,
  and a real CMDB/asset inventory.
- **`lookup_attack_technique` uses simple keyword-overlap scoring**, not the
  TF-IDF/cosine RAG index in `ioc-triage-assistant/`. That project already
  demonstrates retrieval quality in depth; this one's focus is the agent
  loop and tool orchestration around retrieval, not re-proving TF-IDF.
- **The live agent is unit-tested without network access** by injecting a
  fake Anthropic client that returns scripted `tool_use` responses
  (`tests/fakes.py`), so the tool-calling loop logic — multi-tool turns,
  unknown-tool handling, step-budget exhaustion, model stopping without a
  verdict — is verified deterministically in CI.
- **Fail-safe on ambiguity.** If the step budget is exhausted, or the model
  stops without calling `submit_verdict`, the agent returns a `suspicious`
  verdict with low confidence and "escalate to a human analyst" as the
  recommended action, rather than fabricating a confident answer.

## Testing

```bash
pytest -q
```

30 tests cover the individual tools, the offline planner's extraction and
verdict scoring, the live agent's tool-calling loop (via a mocked client),
the live/offline fallback facade, and the CLI itself (as a subprocess, on
human-readable, JSON, and stdin-input paths). No network access or API key
is required to run the suite.
