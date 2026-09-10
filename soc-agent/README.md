# soc-agent

An orchestrator that turns the other three tools in this repo into an
agentic SOC triage pipeline: hand it freeform incident evidence, it decides
which specialist tool(s) apply, runs them, and produces one consolidated
report instead of three disconnected ones.

This is the "glue" project that ties `log-triage-assistant`,
`ioc-triage-assistant`, and `process_threat_hunter` together and
demonstrates the other side of the AI-engineering coin from
`ioc-triage-assistant`'s RAG pipeline: tool orchestration and routing,
rather than retrieval.

## What it does

1. **Route** — an analyst rarely labels their input. Given a blob of raw
   evidence, the router decides whether it looks like auth-log content
   (routes to `log_triage`), alert/IOC-report content (routes to
   `ioc_triage`), both, or neither (falls back to running `ioc_triage` as a
   generalist extractor). Routing is a deterministic regex-based heuristic
   by default, or Claude via tool-calling with `--llm` — either way it
   always explains its reasoning in the output.
2. **Execute** — each selected tool runs as an actual subprocess (`python -m
   <tool>.cli ...`) against the sibling project's own CLI, the same way a
   real agent calls out to external tools. A tool that fails (bad input,
   missing dependency, crash) is reported as an error for that tool instead
   of taking down the run — coverage gaps are surfaced, not hidden.
3. **Aggregate** — per-tool results are normalized onto one severity scale
   (the sibling tools don't even agree on case: `log-triage-assistant`
   emits `"CRITICAL"`, the others emit `"critical"`) and merged into a
   single report: overall severity, total findings, which tools ran/were
   skipped/errored, and a deduplicated, evidence-grounded action list.
4. **Narrate** — a short analyst-readable summary on top of the structured
   report, either a deterministic template or (with `--llm`) Claude —
   shown only the structured findings already produced, and explicitly told
   not to invent facts, the same grounding pattern `log-triage-assistant`
   uses for its narrative.

Scanning the *live host's* processes (`process_threat_hunter`) is never
triggered automatically by the router — it inspects the actual machine the
agent runs on, so it is always an explicit, human-gated `--scan-processes`
flag rather than something a text heuristic or an LLM guess turns on.

## Install

```bash
cd soc-agent
pip install -e ".[dev]"    # pytest, for running the test suite
pip install -e ".[llm]"    # + optional Claude-powered routing/narrative
```

The sibling tools it shells out to are used as subprocesses, not imported,
so their own dependencies (e.g. `process_threat_hunter` needs `psutil`) only
need to be installed in that sibling project's own environment — see each
project's README.

## Usage

```bash
python -m soc_agent.cli --evidence incident.txt
python -m soc_agent.cli --evidence incident.txt --format json --out report.json
python -m soc_agent.cli --evidence incident.txt --scan-processes   # + live host scan
python -m soc_agent.cli --scan-processes                           # live host scan only, no text evidence
python -m soc_agent.cli --evidence incident.txt --llm               # Claude for routing + narrative

# Force or suppress a tool regardless of what the router decides:
python -m soc_agent.cli --evidence incident.txt --force-log --skip-ioc
```

Try it against the included fixtures:

```bash
python -m soc_agent.cli --evidence tests/fixtures/auth_evidence.txt      # routes to log_triage only
python -m soc_agent.cli --evidence tests/fixtures/alert_evidence.txt     # routes to ioc_triage only
python -m soc_agent.cli --evidence tests/fixtures/mixed_evidence.txt     # routes to both, merges results
python -m soc_agent.cli --evidence tests/fixtures/benign_evidence.txt    # no signal, clean report
```

Exit codes mirror `process_threat_hunter`'s convention so this slots into
CI/cron the same way: `0` clean, `1` findings present, `2` every selected
tool failed to run.

## Architecture

```
soc_agent/
  router.py        evidence text -> which tool(s) to run (HeuristicRouter, LLMRouter)
  tools.py          subprocess wrappers around the 3 sibling CLIs -> normalized ToolResult
  aggregator.py     ToolResult[] -> one consolidated report + evidence-grounded action list
  narrative.py      consolidated report -> analyst prose (TemplateNarrator, AnthropicNarrator)
  cli.py            argparse entry point wiring the above together
```

Each stage only depends on the previous stage's output, so routing,
execution, aggregation, and narration are independently unit-testable — see
`tests/`, which covers all four plus CLI end-to-end runs via subprocess
against real evidence fixtures.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The router, aggregator, and narrative tests are pure unit tests. The tool
wrapper tests are split into fast unit tests (subprocess mocked) plus real
subprocess integration tests against `log-triage-assistant` and
`ioc-triage-assistant` (both dependency-free, so these always run); the
`process_threat_hunter` integration test skips itself with a clear reason
if `psutil` isn't installed in this environment, rather than failing.

## Why this design

Real SOC tooling rarely lives in one monolithic script — it's a set of
narrow, independently-maintained detectors and enrichers that something
else has to route between and stitch together for a human to actually read.
This project intentionally keeps that shape: it treats the sibling tools as
black-box CLIs with a JSON contract (not internal imports), normalizes their
disagreements (severity casing, presence/absence of a numeric risk score)
at the boundary instead of upstream, and keeps the risky, host-affecting
action (scanning live processes) outside of anything a heuristic or an LLM
can decide on its own.
