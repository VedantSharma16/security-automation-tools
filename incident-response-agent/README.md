# incident-response-agent

An **agentic** tool-calling loop that autonomously investigates a security
alert: it decides which tool to call next, reads the result, and keeps going
until it has enough evidence to reach a verdict — rather than a single-shot
prompt or a fixed pipeline of steps.

This is a deliberate companion to
[`ioc-triage-assistant`](../ioc-triage-assistant/), which does retrieval
(RAG) in one pass. Here the model (or its offline stand-in) *decides its own
next action* at each turn, based on what it has observed so far — the core
pattern behind agentic SOC/IR copilots.

## How it works

```
Alert  ─▶  Planner.next_step(alert, transcript)  ─▶  ToolCallStep | FinalStep
              ▲                                            │
              │                                            ▼
        append Turn  ◀── execute_tool() against a simulated SOC environment
```

- **`agent/environment.py`** — a read-only, in-memory "SOC": a host
  inventory, per-host running processes, an auth log, and a threat-intel
  feed of known-malicious indicators. Loaded from the JSON/log fixtures in
  `data/`.
- **`agent/tools.py`** — four tools the agent can call: `search_logs`,
  `lookup_ioc`, `get_process_list`, `get_process_detail`. Each has an
  Anthropic-style JSON schema plus a plain dispatch function.
- **`agent/engine.py`** — the loop itself (`investigate()`): repeatedly asks
  a `Planner` for the next step, executes tool calls, and records every step
  in a transcript, until the planner concludes or a turn budget is
  exhausted (in which case the investigation is marked `truncated`/
  `inconclusive` rather than left hanging).
- **`agent/planners.py`** — two interchangeable planners implementing the
  same interface:
  - **`OfflinePlanner`** — a deterministic, dependency-free playbook (pull
    logs → triage any external IPs against threat intel → check running
    processes → pivot on anything suspicious → conclude). Fully
    reproducible, so the entire agent loop is unit-testable without network
    access or an API key.
  - **`ClaudePlanner`** — drives the same loop with real
    [tool use](https://docs.anthropic.com/) against the Claude API when
    `ANTHROPIC_API_KEY` is set, re-rendering the transcript into the prompt
    each turn and parsing either a `tool_use` block or a final JSON verdict.
- **`agent/report.py`** — renders the resulting `InvestigationReport` as
  Markdown or JSON.

## Example

```console
$ pip install -e .
$ ir-agent investigate examples/alert_malicious_web01.json
```

```markdown
# Incident Investigation: Anomalous authentication followed by suspicious process on web01

**Verdict:** MALICIOUS
**Severity:** CRITICAL
**Host:** web01

## Summary
Confirmed malicious activity on web01: indicator(s) 203.0.113.55,
a1b2c3d4e5f6... matched the threat-intel feed. The anomalous process
'kworker/u8:2' (pid 4821) corroborates this. Recommend isolating web01 from
the network, rotating credentials used in the affected session, and
preserving the host for forensic imaging before remediation.

## Investigation transcript
1. `search_logs({'host': 'web01'})` — Establish a timeline for web01 before forming a hypothesis.
2. `lookup_ioc({'indicator': '203.0.113.55'})` — External IP 203.0.113.55 appears in web01's logs; check it against threat intel.
3. `get_process_list({'host': 'web01'})` — Check for suspicious processes currently running on web01.
4. `get_process_detail({'host': 'web01', 'pid': 4821})` — Process 'kworker/u8:2' (pid 4821) has an anomalous command line; inspect it directly.
5. `lookup_ioc({'indicator': 'a1b2c3d4e5f6...'})` — Check the suspicious process's file hash against threat intel.
6. **Conclusion** — Confirmed malicious activity on web01: ...
```

Run the benign example for the contrasting (and shorter) negative path:

```console
$ ir-agent investigate examples/alert_benign_ws-jdoe.json
```

Add `--llm` (with `ANTHROPIC_API_KEY` set) to let Claude drive the
investigation for real instead of the offline playbook; `--format json` for
machine-readable output; `--out report.md` to write to a file.

## Design notes / limitations

- The `ClaudePlanner` re-renders the whole transcript into a fresh prompt
  each turn instead of maintaining a persistent multi-turn conversation.
  That's simpler and keeps the loop's state entirely in the `transcript`
  list (easy to test, log, or replay), at the cost of re-sending context
  each turn — a reasonable trade-off at this scale, but a real production
  agent would likely keep a running message history instead.
- Tools are strictly read-only. Containment/remediation actions
  (isolating a host, disabling an account) are *recommended* in the final
  summary but never executed automatically — a human stays in the loop for
  anything with a blast radius.
- `data/` is a small, fully synthetic SOC environment (fictional hosts, and
  an RFC 5737 documentation-range IP standing in for "the internet") so the
  whole test suite runs offline and deterministically.

## Tests

```console
$ pip install -e ".[dev]"
$ pytest
```

Covers the environment/tool layer, both the offline planner's branching
logic and the full agent loop end-to-end (malicious, benign, and
truncated-investigation paths), report rendering, and the CLI.
