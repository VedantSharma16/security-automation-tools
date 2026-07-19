# logtriage

A command-line tool that parses Linux auth-log style syslogs, runs rule-based
intrusion detectors over them, and produces an incident-response-ready
triage report — optionally with an LLM-written analyst narrative.

It's built around a pattern common in real SOC/IR tooling: **detectors stay
deterministic and auditable; the LLM only writes prose on top of evidence
the detectors already produced.** The model never sees raw logs and is
explicitly instructed not to introduce facts beyond the structured findings
it's given, which keeps the narrative grounded and reviewable.

## What it detects

| Detector | Pattern | Default severity |
|---|---|---|
| Brute force | ≥5 failed SSH logins from one IP within 60s | HIGH |
| Compromise after brute force | A successful login from an IP that just failed ≥3 times | CRITICAL |
| Privilege escalation | `sudo` usage that elevates to root (escalates to CRITICAL if it follows a suspected compromise within 10 minutes) | MEDIUM / CRITICAL |
| Persistence — root account | A new user created with UID 0 | CRITICAL |
| Persistence — crontab | A user's crontab is replaced | MEDIUM |

Findings are combined into a 0–100 risk score and rendered as JSON or
Markdown.

## Install

```bash
cd log-triage-assistant
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
logtriage scan path/to/auth.log
logtriage scan path/to/auth.log --format json --out report.json
logtriage scan path/to/auth.log --window 30 --threshold 8   # tune brute-force sensitivity
logtriage scan path/to/auth.log --llm                       # use Claude for the narrative
```

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic, offline template summarizer — the tool is always usable
without any API key or network access.

Try it against the included fixtures:

```bash
logtriage scan tests/fixtures/sample_auth.log         # simulated compromise + persistence chain
logtriage scan tests/fixtures/sample_auth_clean.log   # benign activity only, zero findings
```

## Architecture

```
logtriage/
  parser.py          syslog line -> structured Event (BSD and ISO8601 timestamps)
  detectors.py        Event list -> Finding list (5 independent, correlatable rules)
  scoring.py          Finding list -> severity breakdown + 0-100 risk score
  report.py            events + findings -> structured report dict, JSON/Markdown rendering
  llm_summarizer.py   report dict -> narrative text (TemplateSummarizer or AnthropicSummarizer)
  cli.py               argparse entry point wiring the above together
```

Each stage takes the previous stage's output and nothing else, so every
piece is independently unit-testable — see `tests/`, which covers the
parser, each detector, scoring, report rendering, the summarizer fallback
logic, and the CLI end-to-end via subprocess.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## Why this design

Real auth-log triage tools (Fail2ban, OSSEC, Wazuh rules) are rule-based for
a reason: determinism and auditability matter when the output drives
account lockouts or escalations. This project keeps that property while
adding an LLM layer purely for what LLMs are actually good at — turning
structured evidence into a readable incident narrative — instead of asking
a model to "read the logs and tell me what happened," which would be far
harder to trust or reproduce.
