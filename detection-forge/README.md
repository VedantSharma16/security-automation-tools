# detection-forge

A **detection-as-code** engine inspired by [Sigma](https://sigmahq.io): write detections as version-controlled rules, unit-test them with embedded positive/negative samples, scan JSONL telemetry, and export ATT&CK coverage. Pure standard library (pytest for tests only).

## Why
Detection engineering is treated as software: rules are reviewed, tested, and measured. This project demonstrates the full loop in ~500 lines.

## Features
- **Rule format** (JSON): `id`, `title`, `level`, `tags` (`attack.tNNNN[.NNN]`), `detection` selections + `condition`.
- **Field modifiers**: `contains`, `startswith`, `endswith`, `re`, `cidr`, `gt/gte/lt/lte`, `exists`, and `all` (combine, e.g. `CommandLine|contains|all`). Dotted paths reach nested fields; string equality is case-insensitive.
- **Condition language**: `and`, `or`, `not`, parentheses, `1 of sel_*`, `all of them` — with a real recursive-descent parser and precise errors.
- **Rule unit tests**: each rule carries `should_match` / `should_not_match` events; `detforge test` fails CI on regressions or untested rules.
- **Strict validation**: unknown modifiers, bad regex/CIDR, undefined selections, malformed ATT&CK tags, duplicate IDs.
- **ATT&CK coverage** report and **Navigator layer** export.
- `scan --fail-on high` returns exit code 2 for pipeline gating.

## Usage
```bash
python -m detforge validate rules
python -m detforge test rules
python -m detforge scan rules samples/events.jsonl [--json] [--fail-on high]
python -m detforge coverage rules --navigator > layer.json
python -m pytest
```

## Example rule
```json
{"id": "DF-004", "title": "Volume shadow copy deletion", "level": "critical",
 "tags": ["attack.t1490"],
 "detection": {
   "vss": {"CommandLine|contains|all": ["vssadmin", "delete", "shadows"]},
   "wmic": {"CommandLine|re": "(?i)wmic.*shadowcopy.*delete"},
   "condition": "vss or wmic"},
 "tests": {"should_match": [{"CommandLine": "vssadmin Delete Shadows /all"}],
           "should_not_match": [{"CommandLine": "vssadmin list shadows"}]}}
```

## Bundled rules
Encoded PowerShell (T1059.001), LSASS access (T1003.001), external SSH failures (T1110.001), shadow-copy deletion (T1490), large non-web egress (T1048).

## Design notes / limits
JSON is used instead of YAML to stay dependency-free; the matching semantics mirror Sigma but this is not a full Sigma implementation (no aggregation/`count()` or correlation rules yet).
