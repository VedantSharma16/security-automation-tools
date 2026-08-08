# Alert Investigator Agent

An agentic, tool-calling investigation loop for SOC alert triage. Given a
raw alert (indicators + affected host + description), the agent decides
*which* tools to call and in *what order* to reach a verdict — it isn't a
fixed pipeline that always runs the same five steps regardless of what it
finds.

This project is the "agentic pipeline" counterpart to
[`ioc-triage-assistant/`](../ioc-triage-assistant/) in this repo, which
demonstrates retrieval (RAG). This one demonstrates the other core applied-AI
pattern: a bounded tool-use loop that gathers evidence, reasons over
intermediate results, and converges on a structured verdict.

## Why this exists

Most "AI agent" demos either hide all the interesting behavior behind an
SDK's agent loop, or fake it with a single LLM call and call it "agentic."
This project keeps the loop itself visible and testable, and — deliberately
— implements the *same* decision logic twice:

- **`planner.py`** is a deterministic, offline "ReAct-style" loop: no LLM
  involved. It still behaves agentically — it skips the alert-history
  lookup when there's no malicious indicator and the asset isn't
  high-value, because that lookup isn't worth the effort in that case. This
  keeps the tool, and its test suite, fully runnable offline.
- **`llm_agent.py`** is the live version: Claude is given the same tool
  registry via the Anthropic tool-use API and asked to investigate,
  calling tools freely and then calling a forced `submit_verdict` tool to
  produce reliable structured output (rather than parsing free text out of
  a final message).
- **`engine.py`** prefers the live agent when `ANTHROPIC_API_KEY` is set,
  and *always* falls back to the offline planner if the live agent errors
  out or fails to converge within its iteration budget. An agentic loop
  that can't reach a conclusion should never leave an alert un-investigated
  — that's a safety property worth designing in, not an afterthought.

## The tool belt

Both agents share one registry (`tools.py`), backed by small local JSON
datasets — no network calls, no external services:

| Tool | Backed by | Purpose |
|---|---|---|
| `lookup_indicator_reputation` | `data/threat_intel.json` | Is this IP/domain known-malicious? |
| `get_asset_context` | `data/asset_inventory.json` | How critical is the affected host? |
| `search_alert_history` | `data/alert_history.json` | Has this indicator fired before, and how did it resolve? |
| `map_mitre_technique` | `data/mitre_playbooks.json` | Does the alert narrative match a known ATT&CK technique, and what's the playbook? |
| `calculate_risk_score` | pure function | Deterministically combine gathered signals into a 0-100 score + band |

Swap any `_load_*` call in `tools.py` for a real SIEM/EDR/threat-intel API
call to take this from demo to production.

## Example investigation trace

Running the bundled example (a brute-forced VPN login followed by beaconing
from a Tor exit node, against the finance database host):

```
$ python -m investigator.cli investigate examples/sample_alert.json
```

The offline planner:

1. Looks up `185.220.101.45` → known-malicious, high confidence.
2. Checks `fin-db-03` → criticality: **critical**.
3. *Because* the indicator is malicious, checks alert history → 2 prior
   true positives for this exact indicator.
4. Maps the narrative text → matches ATT&CK **T1071 (C2)**, pulls its
   playbook.
5. Scores the aggregated signals → **100/100, critical**.
6. Verdict: **TRUE POSITIVE**, high confidence, with the T1071 playbook
   actions plus "escalate to IR" attached.

Change the alert to a clean indicator on a low-criticality dev sandbox and
the trace looks different: the agent skips the history lookup entirely
("no malicious indicator and asset criticality is low/medium — skipping
history lookup to conserve investigation effort") and reaches a low-risk
false-positive verdict in 3 tool calls instead of 5. That branching —
visible in the trace, and asserted on directly in `tests/test_planner.py`
— is the point of the project.

## Quickstart

```bash
cd alert-investigator-agent
pip install -e ".[dev]"        # add ".[llm]" too if you want the live agent
pytest

# Offline planner (default when no API key is set):
python -m investigator.cli investigate examples/sample_alert.json

# JSON output, written to a file:
python -m investigator.cli investigate examples/sample_alert.json --format json --out report.json

# Force the offline planner even if ANTHROPIC_API_KEY is set:
python -m investigator.cli investigate examples/sample_alert.json --no-llm
```

With `ANTHROPIC_API_KEY` set and `pip install -e ".[llm]"`, the same command
runs the live Claude tool-calling loop instead — same tool belt, same
report format, real model reasoning in the trace.

## Project structure

```
alert-investigator-agent/
├── data/                      # local threat intel, asset inventory, alert history, ATT&CK playbooks
├── examples/sample_alert.json
├── investigator/
│   ├── tools.py                # tool implementations + shared registry/schema
│   ├── state.py                # Alert / ToolCall / InvestigationResult dataclasses
│   ├── planner.py               # deterministic offline agentic loop
│   ├── llm_agent.py             # live Claude tool-calling loop (forced submit_verdict)
│   ├── engine.py                 # picks live agent vs. offline planner, with fallback
│   ├── report.py                  # JSON / Markdown rendering
│   └── cli.py
└── tests/                      # 46 tests covering tools, planner branching, engine fallback,
                                 # the LLM loop (via a fake Anthropic client), report rendering, and the CLI
```

## Design notes / what this is meant to demonstrate

- **Bounded autonomy.** The live agent loop has a hard `max_iterations` cap
  and a forced-tool-call pattern (`submit_verdict`) for structured output —
  two concrete answers to "how do you keep an LLM agent loop from running
  away or returning garbage," which matter as much in a security context as
  the investigation logic itself.
- **Same rubric, two implementations.** `planner.py` and `llm_agent.py`
  are required to reach verdicts using the *same* signals and the *same*
  `calculate_risk_score` function, so the offline path isn't a toy stand-in
  — it's a legitimate, auditable agent in its own right, just without an
  LLM making the tool-selection decisions.
- **The LLM loop is tested without any network access or API key**, via a
  fake Anthropic client in `tests/test_llm_agent.py` that scripts a
  multi-turn tool-use conversation. This is the same technique you'd use to
  unit-test any real agentic pipeline in CI.
