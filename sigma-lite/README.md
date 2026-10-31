# sigma-lite

A lightweight **Sigma-compatible detection-as-code engine**. Write detections as
YAML rules, validate them like code, and run them against JSON-lines telemetry
(Sysmon/EDR exports, auth logs, cloud audit logs). Every hit is mapped to
MITRE ATT&CK tactics/techniques and severity, ready for triage or CI gating.

No SIEM required: the matcher is a small, dependency-light implementation
(PyYAML only) so the semantics are easy to read and test.

## Features

- **Sigma detection model**: named selections, maps (AND), lists of maps (OR),
  keyword lists, and value lists (OR).
- **Field modifiers**: `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`,
  plus `*`/`?` wildcards and `null` checks. Case-insensitive by default.
- **Condition grammar**: `and` / `or` / `not`, parentheses, `1 of sel_*`,
  `all of them`, with correct precedence, via a recursive-descent parser.
- **Rule linting**: unknown modifiers, bad regex/CIDR, undefined selections in
  conditions, invalid levels and malformed ATT&CK tags are rejected with clear errors.
- **ATT&CK-aware output**: matches carry techniques, tactics and severity; summary
  rolls up by level and technique.
- **CI-friendly**: `--fail-on-match`, `--min-level`, `--json`, stdin support.

## Usage

```bash
pip install -r requirements.txt
python -m sigmalite validate rules/
python -m sigmalite scan rules/ samples/events.jsonl
python -m sigmalite scan rules/ samples/events.jsonl --json --min-level high
cat events.jsonl | python -m sigmalite scan rules/ - --fail-on-match
```

Example output:

```
[HIGH    ] line 1    Suspicious Encoded PowerShell Command (T1027,T1059.001)
[CRITICAL] line 3    Office Application Spawning Command Shell (T1204.002,T1566.001)
[HIGH    ] line 4    Certutil Used to Download File (T1105)
[CRITICAL] line 5    Volume Shadow Copy Deletion (T1490)
[MEDIUM  ] line 6    Root SSH Login From External Address (T1078)

5 match(es); highest severity: critical
```

## Writing a rule

```yaml
title: Office Application Spawning Command Shell
tags: [attack.execution, attack.t1204.002]
detection:
  parent:
    ParentImage|endswith: ['\winword.exe', '\excel.exe']
  child:
    Image|endswith: ['\cmd.exe', '\powershell.exe']
  filter_helpdesk:
    User: 'NT AUTHORITY\SYSTEM'
  condition: parent and child and not filter_helpdesk
level: critical
```

Five example rules (encoded PowerShell, certutil download cradle, Office macro
child process, shadow-copy deletion, external root SSH) live in `rules/`.

## Layout

```
sigmalite/condition.py   condition tokenizer, parser, evaluator
sigmalite/rule.py        rule schema validation, field matchers, loading
sigmalite/engine.py      event streaming, matches, summary
sigmalite/cli.py         validate / scan commands
rules/  samples/  tests/
```

## Tests

```bash
python -m pytest -q     # 29 tests: modifiers, precedence, quantifiers, linting, end-to-end
```

## Scope / limitations

Implements the commonly used core of the Sigma spec; not supported: `timeframe`
aggregations/`count()`, field-name mappings per backend, and rule conversion to
SIEM query languages (the natural next steps).
