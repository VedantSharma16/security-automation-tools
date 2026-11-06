# sigmalite

A lightweight **detection-as-code** engine for Sigma-style YAML rules. Write detections as
version-controlled rules, validate them in CI, hunt through JSONL telemetry, and measure MITRE
ATT&CK coverage, with no SIEM required.

## Features

- **Sigma-style rules**: named selections, `and` / `or` / `not`, parentheses, `1 of sel_*`, `all of them`.
- **Field modifiers**: `contains`, `startswith`, `endswith`, `re`, `cidr`, `lt/lte/gt/gte`, `exists`, `all`; `*`/`?` wildcards.
  Matching is case-insensitive, lists are OR'd (or AND'd with `|all`), and nested fields work via `process.name`.
- **Strict validation**: unknown modifiers, bad regex/CIDR, undefined or unused selections, invalid levels and duplicate IDs are all rejected with a clear error.
- **ATT&CK coverage report**: techniques per tactic, tactic gaps, and untagged rules.
- **CI-friendly CLI**: `--json`, `--min-level`, `--strict`, `--fail-on-alert`.
- 7 bundled rules (encoded PowerShell, macro-to-shell, LSASS dumping, scheduled-task persistence, shadow-copy deletion, C2 port, account discovery) plus sample telemetry that includes benign events and false-positive filters.

## Usage

```bash
pip install -r requirements.txt
python -m sigmalite validate rules/
python -m sigmalite scan rules/ samples/events.jsonl --min-level medium
python -m sigmalite coverage rules/
```

```
[HIGH    ] line 1    Encoded PowerShell Command (T1027,T1059.001)
[CRITICAL] line 3    LSASS Memory Dump Tooling (T1003.001)
[HIGH    ] line 6    Shadow Copy Deletion (T1490)
```

## Rule example

```yaml
title: Scheduled Task Created From User-Writable Path
id: 7a1c0004-0000-4000-8000-000000000004
level: medium
tags: [attack.persistence, attack.t1053.005]
detection:
  create:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  path:
    CommandLine|contains: ['\AppData\', '\Temp\']
  filter_ms:
    CommandLine|contains: 'Microsoft\Windows'
  condition: create and path and not filter_ms
```

## Design notes

- Rules are compiled once into closures (regexes, CIDR networks and wildcard patterns precompiled), so scanning is a cheap per-event loop.
- Fail-closed authoring: a rule that cannot be fully understood is reported invalid, never silently skipped.
- Coverage attributes each technique to all tactics tagged on the same rule, an approximation (no full ATT&CK matrix is bundled).
- Out of scope: Sigma pipelines/field mappings, `near`/aggregation conditions, backend conversion (Splunk/Elastic).

## Tests

```bash
python -m pytest -q   # 36 tests: matchers, condition grammar, validation, detections, FP filters, CLI
```
