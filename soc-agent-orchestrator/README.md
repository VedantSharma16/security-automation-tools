# SOC Agent Orchestrator

An agentic investigation pipeline that sits on top of this repo's three
specialist security tools (`log-triage-assistant`, `ioc-triage-assistant`,
`process_threat_hunter`) and decides, per case, which of them apply, calls
them, and merges their output into one incident report with an overall
severity, a risk score, and concrete recommended actions.

## Why this exists

The three specialist tools in this repo each do one thing well, but a real
investigation usually needs more than one of them, and *which* ones depends
on what evidence actually landed in the case. This project is the piece
that was missing: an agent that reads a case's evidence, plans which
specialist tools are relevant, runs them, and produces one answer — the
kind of tool-orchestration layer that sits above individual detectors in a
real SOC pipeline. It's also this repo's demonstration of "agentic
pipelines" as a discipline distinct from writing a detector: a genuine
tool-use loop against the Claude Messages API where the model chooses which
tools to call, rather than a hardcoded call sequence.

## How it works

```
                 ┌────────────────────┐
 case directory  │   CaseManifest      │  classify each evidence file:
 (evidence files)│   (case.py)         │  log / alert / other
                 └─────────┬──────────┘
                           │
                 ┌─────────▼──────────┐
                 │      Planner        │  decide which tools apply
                 │      (agent.py)     │
                 └─────────┬──────────┘
             ┌─────────────┼──────────────┐
             ▼             ▼              ▼
     run_log_triage  run_ioc_triage  run_process_hunt
     (tools.py — each wraps a sibling project's own CLI as a subprocess)
             │             │              │
             └─────────────┼──────────────┘
                           ▼
                 ┌────────────────────┐
                 │     Synthesis        │  normalize severities, merge
                 │     (synthesis.py)   │  MITRE techniques, derive
                 └────────────────────┘  recommended actions
```

Two planners are available, chosen automatically based on `ANTHROPIC_API_KEY`
(or forced with `--llm` / `--no-llm`):

- **`LLMPlanner`** — a real Claude tool-use loop. The model is given the
  case manifest and the three tool schemas, and decides which tools apply
  (it's told not to run `run_ioc_triage` on a log file, and not to run
  `run_process_hunt` — which checks the *live* host — unless that's
  relevant to the case) and in what combination, executes them, and writes
  the final analyst narrative once it has enough information.
- **`DeterministicPlanner`** — a fully offline fallback with no API key or
  `anthropic` package required: it runs every specialist tool whose input
  type is present in the case (a `log`-classified file triggers
  `run_log_triage`, an `alert`-classified file triggers `run_ioc_triage`,
  and `run_process_hunt` always runs to check the live host). This is what
  the test suite and CI run against, and it's the default with no API key
  set, so the tool is fully usable offline.

In both cases, **the verdict itself — overall severity, risk score, MITRE
technique list, recommended actions — is always computed deterministically**
in `synthesis.py` from the raw structured tool outputs. The LLM (when used)
only gets to choose *which* tools to call and to write prose; it never gets
to invent a severity or a recommendation, following the same
evidence-grounding discipline as `log-triage-assistant`'s narrative
generator.

Each specialist tool is invoked the same way a human analyst would run it —
as a subprocess CLI call from its own project directory — rather than
imported directly. That keeps this orchestrator, and the three specialist
projects, fully decoupled: each one keeps its own dependencies, its own
test suite, and its own versioning, and none of them need to know the
orchestrator exists.

## Installation

```bash
cd soc-agent-orchestrator
# no hard dependencies for the deterministic planner

# optional, for the LLM planner:
pip install anthropic
export ANTHROPIC_API_KEY=sk-...

# each specialist project needs its own dependencies installed too, e.g.:
pip install -r ../process_threat_hunter/requirements.txt

# for tests:
pip install pytest
```

## Usage

```bash
# Offline, deterministic planner (default without ANTHROPIC_API_KEY)
python -m soc_orchestrator.cli investigate examples/case_webserver_breach

# Force the LLM planner
python -m soc_orchestrator.cli investigate examples/case_webserver_breach --llm

# JSON output, written to a file
python -m soc_orchestrator.cli investigate examples/case_webserver_breach \
    --format json --out report.json

# Force the offline planner even if ANTHROPIC_API_KEY is set
python -m soc_orchestrator.cli investigate examples/case_webserver_breach --no-llm
```

A case directory is just evidence files dropped together:

```
examples/case_webserver_breach/
├── description.txt   # optional free-text incident context
├── auth.log           # classified as "log" -> run_log_triage
└── alert.txt           # classified as "alert" -> run_ioc_triage
```

`run_process_hunt` doesn't take a case file — it always scans whatever host
the orchestrator is running on, to check whether an intrusion described in
the case evidence looks like it's still active.

Running the bundled example against the offline planner produces a
`CRITICAL` / 100-risk-score verdict: the auth log shows an SSH brute force
that succeeds and is followed by root privilege escalation and persistence
(new root-equivalent account, crontab entry), and the alert independently
confirms a live reverse shell and C2 beaconing to indicators already present
in the local threat-intel feed — the same underlying incident, corroborated
from two independent evidence sources.

## Project layout

```
soc_orchestrator/
├── case.py        # evidence file discovery + classification
├── tools.py        # subprocess wrappers around the 3 specialist CLIs + Claude tool schemas
├── agent.py        # LLMPlanner (real tool-use loop) + DeterministicPlanner (offline fallback)
├── synthesis.py    # merges tool outputs into one severity/risk/action verdict
└── cli.py          # `investigate` subcommand, JSON/Markdown output
tests/               # 48 tests: unit tests (mocked subprocess boundary) +
                      # integration tests against the bundled example case
examples/
└── case_webserver_breach/   # a brute-force + C2 case spanning both file types
```

## Tests

```bash
pip install pytest
python -m pytest -q
```

Unit tests mock the subprocess boundary (`tools._run_subprocess`) so they
run fast and don't require the sibling projects' own dependencies (psutil,
anthropic, ...) to be installed. `tests/test_integration.py` exercises the
real subprocess calls against the bundled example case and against the live
host's process list, and is skipped automatically if `psutil` isn't
available.
