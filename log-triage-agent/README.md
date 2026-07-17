# log-triage-agent

A small SOC-style triage tool for SSH/sudo auth logs. It parses raw syslog lines,
runs deterministic detection rules mapped to [MITRE ATT&CK](https://attack.mitre.org/)
techniques, extracts indicators of compromise, and produces an analyst-ready summary —
either from a template or, when an API key is available, from Claude.

It's built to demonstrate two things together: practical blue-team log analysis, and a
clean way to bolt an LLM onto a deterministic pipeline without making the whole thing
depend on the network.

## Why this design

Most "AI security tool" demos either (a) pipe raw logs straight into an LLM and hope it
catches the pattern, or (b) hardcode everything and never touch a model. Neither holds
up well in practice — (a) is non-reproducible and expensive at log volume, (b) can't
explain *why* something matters in plain English for a human analyst.

This tool splits the two concerns:

- **Detection is deterministic.** Brute force, account enumeration, and privilege
  escalation are all threshold/window rules over parsed events — fast, free, testable,
  and the same output every time for the same input.
- **Narration is pluggable.** The `TriageClient` interface has two implementations:
  `DeterministicTriageClient` (template-based, always available, zero dependencies) and
  `AnthropicTriageClient` (calls Claude to turn the findings into a natural-language
  brief with recommended next steps). The CLI picks the LLM client automatically if
  `ANTHROPIC_API_KEY` is set, and falls back to the deterministic one otherwise —
  the tool always works offline.

This mirrors how you'd actually wire an LLM into a larger detection pipeline: keep the
part that needs to be correct and auditable free of model calls, and put the model
behind a narrow seam you can swap, mock, or disable.

## What it detects

| Detector | MITRE ATT&CK | Trigger |
|---|---|---|
| Brute force | T1110 Brute Force | N+ auth failures from one IP within a sliding time window |
| Account enumeration | T1087 Account Discovery | N+ distinct nonexistent usernames probed from one IP |
| Compromised credentials | T1078 Valid Accounts | A successful login from an IP previously flagged for brute-forcing |
| Privilege escalation | T1548.003 Abuse Elevation Control Mechanism | A sudo command granting a shell or modifying accounts/permissions |

## Usage

```bash
pip install -r requirements.txt   # anthropic is optional; only needed for --llm summaries

# Deterministic summary, markdown report
python -m log_triage_agent.cli sample_logs/auth.log --no-llm

# JSON output, for feeding into another tool/dashboard
python -m log_triage_agent.cli sample_logs/auth.log --no-llm --format json

# LLM-generated narrative (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
python -m log_triage_agent.cli sample_logs/auth.log
```

The CLI exits `3` when the highest-severity finding is `critical`, `0` otherwise — useful
as a CI/cron gate (`log-triage-agent auth.log --no-llm || alert`).

### Options

```
--format {markdown,json}   Output format (default: markdown)
--window MINUTES           Brute-force detection window (default: 10)
--threshold N               Failures within the window to flag brute force (default: 5)
--no-llm                    Force the offline summarizer even if ANTHROPIC_API_KEY is set
--year YEAR                  Year to assume for timestamps that omit one (syslog default)
```

### Sample output

Running against `sample_logs/auth.log` (a synthetic incident: brute force → successful
login → privilege escalation, plus an unrelated enumeration attempt and normal user
activity) produces a report with 6 findings, topped by a **CRITICAL** "possible
compromised credentials" finding — see [`sample_logs/auth.log`](sample_logs/auth.log)
to read the story in the raw log.

## Project layout

```
log-triage-agent/
├── src/log_triage_agent/
│   ├── parser.py         # syslog line -> Event
│   ├── detectors.py       # Event stream -> Finding list (MITRE-tagged)
│   ├── ioc.py              # Event stream -> deduplicated IOCs
│   ├── triage_agent.py    # orchestration + pluggable LLM/deterministic narration
│   ├── report.py           # Report -> markdown / json
│   └── cli.py                # argparse entry point
├── tests/                    # pytest, no network required
├── sample_logs/auth.log      # synthetic multi-stage incident for demoing the tool
└── requirements.txt
```

## Testing

```bash
pip install -r requirements.txt
pytest -q
```

27 tests cover the parser (regex correctness on real OpenSSH/sudo line formats),
detectors (threshold/window edge cases, chronological correlation), IOC extraction, the
deterministic narrator, and the CLI end-to-end against the sample log. None of them make
network calls — the Anthropic client is exercised only through its interface via a fake,
so the suite runs the same with or without the SDK installed.

## Known limitations

- Timestamp parsing assumes syslog's traditional `Mon DD HH:MM:SS` format (no year); pass
  `--year` explicitly when triaging archived logs instead of relying on the current year.
- Detection rules are intentionally simple (threshold/window based) rather than
  statistical — they're meant to be transparent and auditable, not to catch a determined
  low-and-slow attacker. A production version would tune thresholds per environment and
  add sequence-based detectors.
- The IP address is trusted as reported in the log line; nothing here corroborates
  against network-layer telemetry.
