# sigma-lite

A small **detection-as-code** engine inspired by [Sigma](https://github.com/SigmaHQ/sigma). Detections are
version-controlled YAML rules, evaluated against JSON/JSONL telemetry (Sysmon, EDR, auth logs, Zeek, ...),
with MITRE ATT&CK mapping and coverage reporting. Built to show how a detection engineer would lint, test
and ship rules the same way software is shipped.

## Features

- **Field modifiers**: `contains`, `startswith`, `endswith`, `re`, `cidr`, `gt/gte/lt/lte`, and `all`
  (`CommandLine|contains|all`). Wildcards (`*`, `?`) in plain values; matching is case-insensitive.
- **Boolean conditions** via a real recursive-descent parser: `and`, `or`, `not`, parentheses,
  `1 of sel_*`, `all of them`. Precedence: `not` > `and` > `or`.
- **Threshold aggregation**: `condition: fail | count() by src_ip >= 5` with `timeframe: 2m`. Uses a per-group
  sliding window; alerts once per burst and re-arms after the window drains (no alert storms).
- **Rule linting**: unknown modifiers, undefined selection names, bad levels, missing timeframes, bad
  regexes and duplicate IDs fail fast with the offending file named.
- **ATT&CK coverage report** and per-alert technique/tactic tags (`attack.t1059.001`).
- Nested events via dotted paths (`event.action`), case-insensitive field names.
- CI-friendly: `--fail-on high` exits `2` when alerts meet the severity floor.

## Usage

```bash
pip install -e ".[dev]"
sigmalite validate rules/
sigmalite run rules/ samples/events.jsonl            # text report
sigmalite run rules/ samples/events.jsonl --json     # machine-readable
sigmalite run rules/ samples/events.jsonl --fail-on high
sigmalite coverage rules/                            # ATT&CK coverage
```

Example rule:

```yaml
title: Office Application Spawning Shell
id: sl-0003
level: high
tags: [attack.initial_access, attack.t1566.001]
detection:
  parent: { ParentImage|endswith: ['\winword.exe', '\excel.exe'] }
  child:  { Image|endswith: ['\cmd.exe', '\powershell.exe'] }
  filter_admin: { User|startswith: 'SVC_' }
  condition: parent and child and not filter_admin
```

Sample output:

```
[CRITICAL] Credential Dumping via comsvcs MiniDump [T1003.001] (1 event(s))
[HIGH    ] Encoded PowerShell Command [T1059.001] (1 event(s))
[HIGH    ] Office Application Spawning Shell [T1566.001] (1 event(s))
[MEDIUM  ] Inbound RDP From Public Address [T1021.001] (1 event(s))
[MEDIUM  ] SSH Brute Force (threshold) [T1110.001] (5 event(s) group=198.51.100.7)
```

## Layout

```
sigmalite/  condition.py (parser) matchers.py (modifiers) rules.py (load/lint) engine.py (run, windows)
            report.py (summary, coverage) cli.py
rules/      example detections      samples/  example telemetry      tests/  34 pytest tests
```

## Tests

```bash
pytest
```

## Scope and limitations

Sigma-*inspired*, not fully Sigma-compatible: no `base64`/`windash` modifiers, no `near`/temporal-sequence
conditions, no backend conversion to Splunk/Elastic queries (a natural next step). Aggregation uses event
timestamps when present and falls back to event order. Sample data is synthetic.
