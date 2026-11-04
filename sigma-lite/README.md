# sigma-lite

A lightweight, **Sigma-compatible detection-as-code engine** in Python. Write detections as YAML, validate them in CI, run them against JSON/JSONL telemetry, and measure MITRE ATT&CK coverage.

## Why
Detection engineering is the blue-team discipline of treating detections like software: versioned, reviewed, tested. This project implements the core of that workflow from scratch (no `pySigma` dependency) to show how rule engines actually work.

## Features
- **Sigma value modifiers:** `contains`, `startswith`, `endswith`, `re`, `cidr`, `lt/lte/gt/gte`, plus `all` (AND across a value list). Case-insensitive, `*`/`?` wildcards.
- **Full condition grammar:** `and` / `or` / `not`, parentheses, `1 of sel_*`, `all of them`, with a proper recursive-descent parser. Unknown selections or empty patterns fail at load time, not at runtime.
- **Lazy, short-circuit evaluation:** each selection is evaluated at most once per event and only if needed.
- **Strict validation:** bad levels, unknown modifiers, invalid regex/CIDR, duplicate rule IDs, malformed conditions all raise clear errors with file paths.
- **ATT&CK coverage report:** technique → rules map, unmapped rules, and a gap analysis against a target technique list.
- **CI-friendly CLI:** `--fail-on-match` exit codes, `--min-level`, `--json` output.
- Safety: regex length cap; nested fields (`a.b`) and list-valued fields supported.

## Usage
```bash
pip install -e ".[dev]"
sigma-lite validate rules/
sigma-lite run rules/ samples/events.jsonl --min-level high
sigma-lite coverage rules/ --target T1059,T1003,T1486   # shows T1486 gap
pytest
```

Example rule (`rules/win_lsass_dump.yml`):
```yaml
title: LSASS Memory Dump via comsvcs or procdump
level: critical
tags: [attack.credential_access, attack.t1003.001]
detection:
  comsvcs:
    CommandLine|contains|all: ['comsvcs', 'MiniDump']
  procdump:
    Image|endswith: '\procdump.exe'
    CommandLine|contains: 'lsass'
  condition: comsvcs or procdump
```

## Layout
```
sigmalite/  matcher.py (modifiers) · condition.py (parser/evaluator) · rule.py (load/validate)
            engine.py (matching, event loading) · coverage.py · cli.py
rules/      5 sample detections mapped to ATT&CK
samples/    mixed malicious + benign events (incl. false-positive filters)
tests/      43 tests: modifiers, condition grammar, rules, engine, CLI
```

## Limitations / next steps
Not a full Sigma implementation (no field-mapping pipelines, `correlation` rules, or `|base64` modifiers, and `logsource` is matched only on `_category/_product/_service` event keys). Natural extensions: backend conversion to Splunk SPL/KQL, and an LLM assistant that drafts rules from threat reports and gates them through this validator and test events.
