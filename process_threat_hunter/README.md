# Process Threat Hunter

A lightweight, cross-platform host-based detection tool that scans running
processes against a rule set of known offensive-security tooling and
living-off-the-land binaries (LOLBins), maps each hit to MITRE ATT&CK, and
can flag processes that weren't present in a previously recorded baseline.

It's a from-scratch, professional rewrite of an earlier one-off script
(`system_logger.py` in the repo root) that shelled out to `tasklist`/`ps` and
matched a flat keyword list. This version replaces that with a proper rule
engine, structured JSON output, ATT&CK mapping, a process baseline/diff
mode, and a test suite.

## Why this exists

Endpoint detection tooling is core to blue-team/IR work: know what's
supposed to be running on a host, alert on what isn't, and be able to
explain *why* something is suspicious (which tactic/technique it maps to).
This project is a small, self-contained demonstration of that model that
runs anywhere Python does — no agent install, no SIEM required.

## Features

- **Rule engine** — YAML-defined rules match a case-insensitive regex
  against a process's name, executable path, and/or full command line.
  Each rule carries a severity (`low`/`medium`/`high`/`critical`) and a
  MITRE ATT&CK tactic + technique ID.
- **Cross-platform process enumeration** via [`psutil`](https://github.com/giampaolo/psutil)
  instead of parsing `tasklist`/`ps` output.
- **Baseline diffing** — snapshot "known good" processes on a host, then
  flag anything that shows up later that wasn't in that baseline,
  independent of whether it also trips a signature rule.
- **Structured JSON reports** for piping into other tooling, plus a
  readable, severity-colored console report.
- **Watch mode** (`--watch SECONDS`) for continuous monitoring instead of a
  single pass.
- **Automation-friendly exit codes** — exits `1` if any finding was
  reported (after the `--min-severity` filter), `0` if clean, so it can gate
  a cron job or CI step.
- 27 unit tests covering rule validation, matching, baselining, reporting,
  and the CLI, all running against mocked process data (no real system
  processes are touched by the test suite).

## Installation

```bash
cd process_threat_hunter
pip install -r requirements.txt
```

## Usage

```bash
# One-shot scan of the local host with the bundled rule set
python -m hunter.cli

# Only show high/critical findings, disable color, write a JSON report
python -m hunter.cli --min-severity high --no-color --json-out report.json

# Record a baseline of "known good" processes
python -m hunter.cli --baseline baseline.json --update-baseline

# Later: scan and flag any process that wasn't in that baseline
python -m hunter.cli --baseline baseline.json

# Continuous monitoring, one scan every 60 seconds
python -m hunter.cli --watch 60

# Use a custom rule file
python -m hunter.cli --rules my_rules.yaml
```

Exit codes: `0` = no findings (after filtering), `1` = findings reported,
`2` = a fatal error (e.g. missing rule file).

## Rule format

```yaml
- id: credential-dumping-mimikatz
  pattern: 'mimikatz'
  match_fields: [name, exe, cmdline]
  severity: critical
  mitre_tactic: Credential Access
  mitre_technique: T1003
  description: Mimikatz is a widely used credential dumping tool.
```

`match_fields` is any subset of `name`, `exe`, `cmdline`. The bundled
[`rules/default_rules.yaml`](rules/default_rules.yaml) covers credential
dumping tools, C2 frameworks, lateral movement/AD attack tooling,
Kerberos attacks, network/web recon tooling, password cracking, LOLBins,
obfuscated PowerShell, scheduled-task persistence, and reverse-shell
netcat usage — 18 rules in total, each with a rationale and ATT&CK
mapping.

**Note:** these are broad, illustrative signatures, not a production
detection ruleset. Legitimate admin and security tooling (e.g. `nmap`,
`wireshark`, `powershell.exe`) will also trip several of these rules — tune
`match_fields`/patterns and add allow-listing before running this
unattended in an environment where those tools are expected.

## Project layout

```
process_threat_hunter/
├── hunter/
│   ├── rules.py      # rule loading/validation, regex matching
│   ├── scanner.py     # psutil-based process enumeration + evaluation
│   ├── baseline.py    # save/load/diff known-good process snapshots
│   ├── report.py       # console + JSON report rendering
│   └── cli.py           # argparse entry point
├── rules/
│   └── default_rules.yaml
├── tests/
│   ├── test_rules.py
│   ├── test_scanner.py
│   ├── test_baseline.py
│   ├── test_report.py
│   └── test_cli.py
├── requirements.txt
└── requirements-dev.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Possible extensions

- Ship additional rule packs (e.g. cloud CLI abuse, cryptominer signatures).
- Add a `--syslog`/webhook sink for alerting instead of only files/stdout.
- Correlate findings with process parent/child trees to reduce noise from
  legitimate admin tooling.
