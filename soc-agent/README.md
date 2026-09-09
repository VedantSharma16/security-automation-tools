# SOC Agent

An autonomous, tool-calling SOC tier-1 triage agent. Given a raw security
alert, it investigates the way a junior analyst would — pull threat-intel
on any indicators, grep the relevant host logs, check MITRE ATT&CK context,
verify unfamiliar processes against a baseline — and only then produces a
structured verdict with a severity rating and recommended next steps.

## Why this exists

The other tools in this repo (`log-triage-assistant/`, `ioc-triage-assistant/`)
demonstrate rule-based detection and single-shot, RAG-grounded summarization:
the pipeline is fixed, and an LLM (when available) writes the closing
narrative from a context object it's handed. This project demonstrates the
other major LLM application pattern — an **agentic pipeline**: the model
itself decides which tools to call, in what order, and when it has enough
evidence to conclude, via a bounded reason → act → observe loop (Claude's
tool-use API). That's a meaningfully different engineering problem: instead
of validating one prompt's output, you have to design a tool contract the
model can use correctly, and guard against the failure modes that only show
up in a loop — the model calling tools forever, or stopping before it has
enough evidence.

## How the agent loop works

1. The agent is given the alert text, a system prompt describing its role,
   and a fixed set of tool definitions (JSON Schema, via Claude's tool-use
   API).
2. Each turn, it can call zero or more tools. The orchestrator executes
   whatever it asks for against real local data and feeds the results back
   as the next turn's context.
3. This repeats until the model calls `finish_investigation` — a terminal
   tool whose arguments *are* the structured verdict — or a **step budget**
   (default 8) is exhausted, which raises `InvestigationIncomplete` rather
   than silently returning nothing. An agent that can loop can also loop
   forever; treating "ran out of steps" as a hard failure, not a warning, is
   the difference between a demo and something you'd actually run.

```
  alert text
      │
      ▼
 ┌─────────┐   tool call    ┌──────────────────────────┐
 │  agent  │ ─────────────▶ │ check_ioc_reputation      │
 │ (LLM or │                │ search_logs                │
 │ offline │ ◀───────────── │ lookup_attack_technique    │
 │ planner)│   tool result  │ check_process_baseline     │
 └────┬────┘                └──────────────────────────┘
      │ finish_investigation(severity, summary, ...)
      ▼
   Verdict + full transcript
```

### Tools available to the agent

| Tool | Backed by |
|---|---|
| `check_ioc_reputation` | Local threat-intel feed (`data/threat_intel.json`) |
| `search_logs` | The host log file passed in for this investigation |
| `lookup_attack_technique` | Small local MITRE ATT&CK keyword reference (`data/attack_techniques.json`) |
| `check_process_baseline` | Known-good process allowlist (`data/process_baseline.json`) |
| `finish_investigation` | Terminal — ends the loop with a structured verdict |

## Live mode vs. offline mode

Live mode (`ANTHROPIC_API_KEY` set + `anthropic` installed) lets Claude
actually decide the investigation path per alert.

Without a key, `SocAgent.investigate()` falls back to a **deterministic
offline planner** (`soc_agent/offline_planner.py`) that drives the *exact
same* tool functions through scripted logic: extract obvious leads (IPs,
usernames, suspicious process names) from the alert text, investigate each
one, and score severity from what comes back. It's not a mock — it's a real,
rule-based decision-maker standing in for the LLM, which is what keeps the
whole pipeline (tool dispatch, the transcript, report rendering, the CLI)
runnable and unit-tested with no credentials or network access, matching
the offline-first pattern used elsewhere in this repo. The trade-off is
honest: the offline planner only handles the patterns it was scripted for,
where the live agent can reason about a case it's never seen.

Severity is deliberately *not* driven by ATT&CK keyword matches alone in
the offline planner — "Valid Accounts" fires just as readily on a routine
successful login as on a real compromise, so it's kept as informational
context. Severity comes from things that actually indicate anomalous
behavior: a known-malicious indicator, a confirmed brute-force pattern in
the logs, or a process outside the host's baseline.

## Installation

```bash
cd soc-agent
pip install -e .          # offline mode only
pip install -e ".[llm]"   # + live mode (installs the anthropic SDK)
```

## Usage

```bash
# Offline mode (no API key needed) — investigate the bundled example alert
soc-agent investigate --alert examples/alert_bruteforce_compromise.txt \
                       --logs examples/sample_auth.log

# A benign alert, for contrast
soc-agent investigate --alert examples/alert_benign_login.txt

# Live mode: set ANTHROPIC_API_KEY and install the llm extra, same command
export ANTHROPIC_API_KEY=sk-ant-...
soc-agent investigate --alert examples/alert_bruteforce_compromise.txt --logs examples/sample_auth.log

# Write the full structured report (verdict + tool-call transcript) as JSON
soc-agent investigate --alert examples/alert_bruteforce_compromise.txt \
                       --logs examples/sample_auth.log --json-out report.json

# CI-friendly: exit 1 only at/above a given severity (default: high)
soc-agent investigate --alert examples/alert_benign_login.txt --fail-on-severity critical
```

Exit codes: `0` = severity below the `--fail-on-severity` threshold,
`1` = at/above it, `2` = a fatal error (bad alert path, or the agent
exhausted its step budget without concluding).

### Example output

```
$ soc-agent investigate --alert examples/alert_bruteforce_compromise.txt --logs examples/sample_auth.log
============================================================
SOC AGENT INVESTIGATION REPORT  [offline mode]
============================================================
Severity: CRITICAL
Steps taken: 5

Summary:
  Known-malicious indicator(s) observed: 203.0.113.77 (Repeated credential-stuffing
  source flagged by an upstream sharing feed on 2026-08-14.). Log evidence shows
  repeated failed authentication followed by a successful login for the same
  source, consistent with a successful brute-force attempt. Alert language most
  closely matches: T1110 Brute Force, T1078 Valid Accounts, T1021 Remote Services.

Recommended actions:
  1. Isolate the affected host from the network immediately.
  2. Force a password reset and revoke active sessions for: admin.
  3. Block outbound/inbound traffic to 203.0.113.77 at the perimeter firewall.
  4. Escalate to tier-2/IR for full compromise assessment and evidence preservation.
------------------------------------------------------------
Investigation transcript (tool calls the agent made):
  [1] check_ioc_reputation(indicator='203.0.113.77')
      -> {'known_malicious': True, 'source': 'demo-feed', ...}
  [2] search_logs(query='203.0.113.77')
      -> {'total_matches': 8, ...}
  ...
```

## Using it as a library

```python
from soc_agent import SocAgent

agent = SocAgent()  # live if ANTHROPIC_API_KEY is set, offline otherwise
verdict, transcript = agent.investigate(alert_text, log_path="auth.log")

print(verdict.severity, verdict.summary)
for step in transcript:
    print(step.tool, step.arguments, "->", step.result)
```

## Project layout

```
soc-agent/
├── soc_agent/
│   ├── tools.py             # tool implementations, JSON-Schema specs, ToolContext, Verdict
│   ├── agent.py             # SocAgent — the bounded live tool-calling loop
│   ├── offline_planner.py   # deterministic stand-in for the LLM decision-maker
│   ├── report.py            # text/JSON rendering, CI exit-code logic
│   └── cli.py                # argparse entry point
├── data/
│   ├── threat_intel.json
│   ├── attack_techniques.json
│   └── process_baseline.json
├── examples/
│   ├── alert_bruteforce_compromise.txt
│   ├── alert_benign_login.txt
│   └── sample_auth.log
└── tests/
    ├── test_tools.py
    ├── test_offline_planner.py
    ├── test_agent.py          # scripted fake Anthropic client, no network needed
    ├── test_report.py
    └── test_cli.py
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

34 tests, all offline — the live loop is exercised with a scripted fake
Anthropic client (`tests/test_agent.py`) that returns canned `tool_use`
responses, so the loop's dispatch, multi-tool-call, and step-budget logic
are all covered without needing a real API key.

## Possible extensions

- Swap the offline planner's regex-based extraction for the IOC extractor
  already built in `ioc-triage-assistant/` for richer indicator coverage
  (hashes, domains, defanged IOCs).
- Give the agent a `pivot_search` tool that re-queries logs for indicators
  *discovered* mid-investigation (e.g. a second IP seen in a matched log
  line), to show genuinely adaptive, multi-hop tool use.
- Add a streaming/verbose CLI mode that prints each tool call as the agent
  makes it, instead of only after the loop concludes.
