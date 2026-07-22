# ir-agent

An agentic incident-response investigator: given a raw security alert or log
excerpt, an LLM tool-use agent decides *for itself* which investigation
tools to call, in what order, reads each tool's output, and finishes by
submitting a structured incident report — severity, key indicators, MITRE
ATT&CK techniques, and recommended actions for the on-call analyst. Without
an API key, a deterministic offline pipeline runs the same tools in a fixed
order and produces the same report shape, so the project is fully runnable
and testable with no network access or API cost.

## Why this exists

This repo's other AI-security projects ([`ioc-triage-assistant`](../ioc-triage-assistant/),
[`log-triage-assistant`](../log-triage-assistant/)) are single-pass
pipelines: fixed step A → step B → step C, with an LLM used only at the end
to narrate the result. That's a common and useful shape, but it isn't
*agentic* — nothing in those pipelines decides what to do next based on
what it just learned.

`ir-agent` is deliberately built around a real ReAct-style tool-use loop
instead:

- The agent gets a system prompt describing four tools and a goal, not a
  fixed procedure.
- It chooses which tools to call — it can skip `analyze_auth_log` entirely
  if the incident text has no log lines, or call `map_attack_techniques`
  before or after enrichment, depending on what it decides it needs.
- It must **finish by calling a tool**, `submit_incident_report`, whose
  JSON-schema-constrained arguments *are* the final report. There's no
  free-text answer to parse and hope is well-formed — the same mechanism
  that gives the agent typed tool inputs also gives you a typed, validated
  final answer.
- If the model never calls `submit_incident_report` (loses the plot, hits
  the turn limit, or the API call fails outright), the agent falls back to
  the deterministic offline pipeline using whatever it already gathered, so
  a single flaky LLM call never produces "no report at all."

## Architecture

```
incident text
      │
      ▼
IncidentResponseAgent.investigate()
      │
      ├── live mode (ANTHROPIC_API_KEY set) ─────────────────────────┐
      │     Claude drives a tool-use loop, choosing among:            │
      │       • extract_iocs           (ir_agent/tools/ioc_extraction.py)
      │       • enrich_indicators      (ir_agent/tools/enrichment.py)
      │       • analyze_auth_log       (ir_agent/tools/log_analysis.py)
      │       • map_attack_techniques  (ir_agent/tools/mitre_mapping.py)
      │     ...until it calls submit_incident_report (forced on the     │
      │     final turn via tool_choice if it hasn't finished by then)   │
      │                                                                 │
      └── offline mode (no key) ───────────────────────────────────────┘
            Same four tools, called in a fixed sensible order; severity,
            summary, and recommendations synthesized by plain heuristics
            instead of an LLM.
      │
      ▼
AgentResult (severity, summary, key_indicators, attack_techniques,
             recommended_actions, tool-call transcript)
      │
      ▼
report.py → Markdown or JSON
```

Every tool is a plain, deterministic Python function with no LLM
dependency and no side effects on each other — the "intelligence" (deciding
what to call, when, and how to interpret results) is confined entirely to
`agent.py`. That separation is what makes both modes testable: the tools
are unit-tested directly, the offline orchestrator is tested for
deterministic output, and the live loop is tested by stubbing the Anthropic
client's `.messages.create()` with scripted tool-use responses — no real
API calls, no `anthropic` package installation, required to verify the
loop's control flow (multi-tool dispatch, forced finalization, fallback on
failure).

## Quickstart

```bash
cd ir-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live agent
pytest -q

ir-agent --file examples/sample_incident.txt
ir-agent --file examples/sample_incident.txt --json
cat examples/sample_incident.txt | ir-agent
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m ir_agent.cli --file examples/sample_incident.txt
```

### Enabling the live agent

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
ir-agent --file examples/sample_incident.txt
```

Without a key, the report's `"mode"` field reads `"offline"` (or
`"live-fallback"` if a key is set but the model never finalized) instead of
`"live"` — everything else about the report shape is identical.

## Example output

Running against `examples/sample_incident.txt` (brute-forced SSH login,
followed by a successful auth from the same IP, a malware download, and a
crontab persistence mechanism) in offline mode:

```
🔴 Severity: CRITICAL
Agent mode: offline

Summary: Extracted 4 indicator(s) from the supplied incident text.
Known-malicious indicators observed: 45.148.10.94 (ip), 91.219.236.18 (ip),
http://45.148.10.94/update.php (url), e99a18c428cb38d5f260853678922e03
(hash). Brute-force login attempts detected from 91.219.236.18. A
successful login followed brute-force attempts from 91.219.236.18 — likely
compromise. 1 persistence-related event(s) observed (new accounts and/or
crontab edits). Behavior most closely resembles ATT&CK technique T1110
(Brute Force).

Key indicators: 45.148.10.94, 91.219.236.18,
http://45.148.10.94/update.php, e99a18c428cb38d5f260853678922e03

ATT&CK techniques: T1110, T1078, T1548.003

Recommended actions:
1. Isolate the affected host(s) from the network pending investigation.
2. Block the flagged indicators at the firewall/EDR and pivot on them
   across the SIEM for related activity.
3. Force a password reset for any accounts logged in from
   91.219.236.18 and review their session history.
4. Audit newly created accounts and crontab entries for unauthorized
   persistence.
```

## Project layout

```
ir-agent/
├── ir_agent/
│   ├── agent.py             # the ReAct loop + offline fallback orchestrator
│   ├── schemas.py            # Anthropic tool-use JSON schemas (incl. submit_incident_report)
│   ├── report.py             # Markdown / JSON rendering of an AgentResult
│   ├── cli.py                 # argparse CLI
│   └── tools/
│       ├── ioc_extraction.py  # regex IOC extraction + defanging
│       ├── enrichment.py       # local threat-intel lookup
│       ├── log_analysis.py    # brute force / compromise / persistence detection
│       └── mitre_mapping.py   # keyword-based ATT&CK technique mapping
├── data/
│   ├── known_malicious_indicators.json
│   └── mitre_attack_techniques.json
├── examples/sample_incident.txt
└── tests/                     # pytest, fully offline
```

## Design notes / limitations

- **Threat-intel feed and ATT&CK keyword map are both small, synthetic
  datasets** for demo purposes, not live intelligence — the same caveat as
  the sibling projects in this repo.
- **`map_attack_techniques` uses keyword overlap, not embeddings or
  TF-IDF/cosine retrieval.** `ioc-triage-assistant` already demonstrates a
  from-scratch RAG index over the same kind of ATT&CK dataset; this project
  intentionally uses a different, simpler technique so the two aren't
  redundant.
- **The agent can only call four tools and one finalize action.** A larger
  agent would add tools like host/EDR queries, DNS reputation lookups, or a
  ticketing-system call — the loop and forced-finalization pattern here
  scale to that without changes to `agent.py`'s control flow.
- **`max_tool_turns` defaults to 8** and forces `tool_choice` to
  `submit_incident_report` on the final turn, so a live run always
  terminates in a bounded number of API calls even if the model would
  otherwise keep investigating indefinitely.

## Testing

```bash
pytest -q
```

38 tests cover IOC extraction (including defanging and trailing-punctuation
stripping), threat-intel enrichment, log analysis (brute force, compromise,
privilege escalation, persistence), ATT&CK keyword mapping, the
deterministic offline pipeline end-to-end, the live tool-use loop's control
flow (multi-tool dispatch, forced finalization, fallback on both a
non-finalizing model and a raised client exception) via a stubbed Anthropic
client, report rendering, and the CLI itself as a subprocess. No network
access or API key is required to run the suite.
