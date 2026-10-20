# sigma-lite

A small, **dependency-free** detection engine that runs [Sigma](https://github.com/SigmaHQ/sigma)-style
rules against JSON/NDJSON event logs and reports hits sorted by severity with MITRE ATT&CK technique
mapping. Built to demonstrate detection-engineering fundamentals: rule languages, condition parsing,
false-positive filtering, and CI-friendly exit codes.

## Features

- Sigma rule subset: selections (maps, lists of maps = OR, keyword lists), field modifiers
  `contains`, `startswith`, `endswith`, `re`, `all`, `cased`, `*`/`?` wildcards, null matching, dotted nested fields.
- Full condition grammar: `and` / `or` / `not`, parentheses, `1 of sel_*`, `all of them` (correct precedence).
- Built-in YAML-subset parser, so there is no PyYAML requirement.
- Strict rule validation (undefined selections, bad modifiers/levels/regexes) with file-qualified errors.
- ATT&CK technique/tactic extraction from `attack.*` tags; `--min-level` filter; text or JSON output.
- Exit codes for pipelines: `0` no matches, `1` matches, `2` rule/event errors.

## Usage

```bash
python -m sigmalite validate --rules rules/
python -m sigmalite scan --rules rules/ --events samples/events.json
python -m sigmalite scan --rules rules/ --events samples/events.json --min-level high --format json
```

Sample output:

```
6 events, 4 rules -> 4 match(es)
[CRITICAL] Credential Dumping via comsvcs MiniDump (T1003.001) events=[4]
[CRITICAL] Office Application Spawning Shell (T1204.002) events=[2]
[HIGH    ] Suspicious Encoded PowerShell Command (T1059.001) events=[1]
[MEDIUM  ] Local Account Added To Administrators (T1098) events=[5]
```

Note the `office-spawns-shell` rule uses a `filter_legit` selection: event 3 (an approved macro tool) is
correctly *not* flagged.

## Layout

```
sigmalite/  yamlsubset.py  rules.py  condition.py  engine.py  cli.py
rules/      4 example rules (PowerShell, macro malware, LSASS dump, admin add)
samples/    example events
tests/      20 pytest tests
```

## Tests

```bash
pip install pytest && python -m pytest
```

## Limitations

Not a full Sigma implementation: no aggregation (`count() by`), `near`/temporal conditions, field
mappings/pipelines, or rule correlation. Those are natural next steps (a backend that compiles rules to
Splunk/Elastic queries would be the obvious one).
