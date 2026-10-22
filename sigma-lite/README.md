# sigma-lite

A lightweight, Sigma-compatible **detection-as-code** engine. Write detections as
YAML, validate them like code, run them against JSON/JSONL telemetry, and see
which MITRE ATT&CK techniques your rule set covers.

Built to demonstrate blue-team detection engineering: rule authoring, a real
condition-expression parser, false-positive filtering, and CI-friendly exit codes.

## Features

- **Sigma rule subset**: selections as maps, lists of maps (OR) or keyword lists.
- **Field modifiers**: `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`,
  `lt/lte/gt/gte`, `exists`; case-insensitive matching with `*`/`?` wildcards.
- **Condition language** (recursive-descent parser): `and`, `or`, `not`, parentheses,
  `1 of sel_*`, `all of them`.
- **Nested events**: `src.ip` resolves both literal dotted keys and nested objects.
- **Strict validation**: unknown modifiers, bad regex/CIDR, undefined selections in
  conditions and invalid levels are rejected at load time, not at match time.
- **ATT&CK coverage report** from rule tags (`attack.t1059.001`, tactics).
- **CI mode**: `--fail-on-match` exit code; `validate` for rule linting in pipelines.

## Usage

```bash
pip install -r requirements.txt
python -m sigmalite validate rules/
python -m sigmalite scan rules/ samples/events.jsonl --min-level medium
python -m sigmalite scan rules/ samples/events.jsonl --json
python -m sigmalite coverage rules/
```

Example output:

```
Scanned 7 event(s) with 5 rule(s): 6 alert(s)
  [CRITICAL] event #3: LSASS Memory Dump via Common Tools (T1003.001)
  [HIGH    ] event #1: Suspicious Encoded PowerShell Command (T1027,T1059.001)
  ...
```

## Example rule

```yaml
title: Office Application Spawning Shell
tags: [attack.execution, attack.t1204.002, attack.t1059]
detection:
  parent: {ParentImage|endswith: ['\winword.exe', '\excel.exe']}
  child:  {Image|endswith: ['\cmd.exe', '\powershell.exe']}
  filter_legit: {CommandLine|contains: 'C:\CorpTools\approved.cmd'}
  condition: parent and child and not filter_legit
level: high
```

## Layout

```
sigmalite/   condition.py (parser), matchers.py, rule.py, engine.py, coverage.py, cli.py
rules/       5 sample detections (PowerShell, LSASS, macros, SSH, schtasks)
samples/     sample event stream
tests/       43 pytest tests
```

## Tests

```bash
python -m pytest
```

## Limitations

Not a full Sigma implementation: no `timeframe`/aggregation (`count() > N`), no
`base64offset`/`windash` modifiers, no logsource-to-field mapping pipelines.
Rules are matched against events as-is.
