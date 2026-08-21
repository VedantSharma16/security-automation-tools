# Incident Response Agent

A ReAct-style, tool-calling agent that investigates a security incident the
way a SOC analyst would: read the report, decide which lookups are worth
doing, run them one at a time, and only then commit to a severity and a set
of next steps — with the full reasoning trace kept alongside the verdict.

This is deliberately *not* a single-shot "summarize this alert" LLM call.
Each investigation is a loop of `Thought -> Action -> Observation` steps
over a small toolset, which is what makes it an **agentic pipeline** rather
than a RAG or classification pipeline: the model (or, offline, a
deterministic policy standing in for one) decides what to look up next
based on what it has learned so far, and decides for itself when it has
enough evidence to stop.

## Why two planners

| | Offline planner | LLM planner |
|---|---|---|
| Requires | nothing | `ANTHROPIC_API_KEY` + `pip install '.[llm]'` |
| Tool-call order | fixed priority queue (CVEs → IPs → domains → ATT&CK match) | decided by the model, turn by turn |
| Determinism | fully deterministic, safe for CI | non-deterministic, network-dependent |
| Verdict | rule-based scoring (`synthesis.py`) | the model's own structured `finish` call |

`run_agent()` prefers the LLM planner when a key is available and falls
back to the offline planner if the SDK is missing, the key is unset, or the
live call fails for any reason (rate limit, network error, malformed tool
call) — an incident always gets a verdict. The offline planner also makes
the *orchestration logic itself* (tool selection, step budget, evidence
scoring) fully unit-testable without mocking an LLM for every test.

## How the loop works

1. **Extract entities.** Regex over the incident text pulls out CVE IDs,
   IPv4 addresses, and domains (`ir_agent/entities.py`).
2. **Investigate.** The agent calls tools one at a time — `check_cve`,
   `check_ip_reputation`, `check_domain_reputation`, `lookup_attack_technique`
   — each backed by a small local JSON dataset (`data/`), and records a
   `Thought` + the tool's `Observation` as an `AgentStep`.
   - *Offline planner*: works a fixed queue built from extracted entities,
     then a final ATT&CK keyword match over the full text.
   - *LLM planner*: a real Anthropic tool-use loop (`ir_agent/llm_agent.py`)
     — the model reads each observation and decides the next tool call (or
     to call `finish`) itself, capped at `max_steps`.
3. **Synthesize a verdict.** Severity, confidence, and recommended actions
   are derived from the gathered evidence — either by the offline scoring
   rules in `synthesis.py`, or, in LLM mode, directly from the model's own
   structured `finish` tool call (falling back to the same scoring rules if
   the model runs out of steps without finishing).

## Usage

```bash
pip install -e .            # offline planner only
pip install -e '.[llm]'     # + live Anthropic tool-use planner

ir-agent --file examples/sample_incident.txt
ir-agent --file examples/sample_incident.txt --json
ir-agent --file examples/sample_incident.txt --offline   # force the deterministic planner
cat examples/sample_incident.txt | ir-agent
```

Example (offline planner, no API key needed):

```
🔴 Severity: CRITICAL  (confidence 0.80)
Planner: offline deterministic

Agent trace (5 step(s)):
  1. [check_cve] Incident text references CVE-2021-44228; checking severity and exploitation status.
     -> CVE-2021-44228 (Log4Shell) has CVSS 10.0, severity critical. It is listed as known-exploited in the wild.
  2. [check_ip_reputation] Incident text references IP 45.155.205.28; checking local threat-intel reputation.
     -> 45.155.205.28 is a known-malicious indicator (high confidence): Cobalt Strike C2 rendezvous point observed in prior incidents.
  ...

Recommended actions:
  - Block/monitor known-malicious IP(s) at the perimeter: 45.155.205.28.
  - Patch or compensating-control affected systems for actively exploited CVE-2021-44228 immediately.
  - Isolate the affected host(s) pending analyst confirmation.
```

## Design notes

- **Grounded, not hallucinated.** The LLM planner's system prompt requires
  every claim in the final summary to come from a tool observation, and the
  agent is instructed to investigate every entity mentioned before
  finishing — mirroring how you'd want a junior analyst-assistant to behave.
- **Bounded.** `max_steps` caps both planners; the offline planner reports
  in its own trace when it had to stop with items still queued, and the LLM
  planner falls back to rule-based synthesis rather than failing silently
  if it exhausts its step budget without calling `finish`.
- **Local, inspectable data.** Threat intel, the CVE database, and ATT&CK
  technique keywords are small bundled JSON files (`data/`) rather than
  live API calls — deliberate, so the tool is fully offline-runnable and the
  test suite never depends on network access or rate limits.

## Tests

```bash
pip install -e '.[dev]'
pytest
```

31 tests cover entity extraction, each tool in isolation, the offline
scoring/severity logic, the offline planner's loop (including step-budget
truncation and full determinism), the LLM tool-use loop (via a fake
Anthropic client that exercises multi-turn tool execution, message
threading, and both the direct-`finish` and ran-out-of-steps paths), and
the CLI.

## Relationship to the other projects in this repo

[`ioc-triage-assistant/`](../ioc-triage-assistant/) also uses an LLM, but as
a single retrieval-augmented summarization call over pre-computed context.
This project is the agentic counterpart: the model itself drives a
multi-step tool-use loop, deciding what to investigate next rather than
having all context handed to it up front.
