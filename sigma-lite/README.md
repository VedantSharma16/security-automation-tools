# sigma-lite

A small, dependency-light **Sigma-style detection engine**. Write detections as
YAML, run them against JSON/NDJSON events, and get an ATT&CK coverage report for
your rule set. Built to show detection-engineering fundamentals: rule languages,
boolean condition parsing, false-positive filtering, and coverage thinking.

## Features
- **Sigma-compatible rule subset**: `selection` maps (AND of fields), lists of maps (OR),
  and `condition` expressions with `and` / `or` / `not`, parentheses, `1 of sel_*`,
  `all of them`.
- **Value modifiers**: `contains`, `startswith`, `endswith`, `re`, `all`, `cased`,
  `lt/lte/gt/gte`; case-insensitive by default, `*`/`?` wildcards, dotted nested fields.
- **Hand-written recursive-descent condition parser** (no `eval`), with clear errors for
  unknown selections or malformed expressions.
- **Validation**: required fields, severity levels, duplicate rule IDs.
- **ATT&CK coverage report** (`attack.tXXXX` / tactic tags) highlighting tactic gaps.
- Exit codes suitable for CI: `scan` returns 1 on alerts, 2 on errors.

## Usage
```bash
pip install -e .[dev]
sigmalite validate rules/
sigmalite scan rules/ tests/fixtures/events.ndjson --min-level high
sigmalite scan rules/ events.json --json
sigmalite coverage rules/
```

Example rule (`rules/lsass_access.yml`):
```yaml
title: Credential Dumping via LSASS Access
id: sl-0002
tags: [attack.credential-access, attack.t1003.001]
level: critical
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains: ['0x1010', '0x1410', '0x1fffff']
  filter_system:
    SourceImage|startswith: 'C:\Windows\System32\'
  condition: selection and not filter_system
```

## Layout
```
sigmalite/  condition.py  matchers.py  rule.py  engine.py  coverage.py  cli.py
rules/      five example detections (PowerShell, LSASS, schtasks, VSS deletion, lateral movement)
tests/      28 tests incl. benign-event negatives and an end-to-end fixture
```

## Tests
```bash
pytest
```

## Limitations
Not a full Sigma implementation: no aggregation (`count() by`), `near`/temporal
conditions, field-mapping pipelines, or `|base64`/`|cidr` modifiers. Those are natural next steps.
