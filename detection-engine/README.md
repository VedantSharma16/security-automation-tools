# sigmalite: detection-as-code engine

A small, dependency-free detection engine that evaluates **Sigma-style rules**
against JSONL events (EDR/Sysmon exports, auth logs, cloud audit logs) and
reports which MITRE ATT&CK techniques your rule set actually covers.

Detection engineering treats detections like software: rules are versioned
files, linted in CI, and tested against known-good and known-bad events. This
project is a compact implementation of that workflow.

## Features

- **Sigma-like rule format** (JSON, so no YAML dependency): named selections,
  `condition` expressions with `and` / `or` / `not`, parentheses, `1 of sel*`,
  `all of them`.
- **Field modifiers**: `contains`, `startswith`, `endswith`, `re`, `all`;
  case-insensitive matching, nested fields via dotted paths, `null` for "field absent".
- **Rule linting**: unknown selections, selections never used by the condition,
  bad regexes, invalid levels, and duplicate IDs are rejected with clear errors.
- **ATT&CK coverage report** from rule tags (`attack.t1059.001`, `attack.persistence`).
- **CI-friendly CLI**: `scan` exits `2` when alerts fire, `1` on errors.
- Severity filtering (`--min-level`) and JSON output.

## Usage

```bash
pip install -e .[dev]            # or just run `python -m sigmalite` from this folder
python -m sigmalite validate rules/
python -m sigmalite scan rules/ samples/events.jsonl --min-level high
python -m sigmalite coverage rules/ --json
cat events.jsonl | python -m sigmalite scan rules/ -
```

Sample output:

```
[CRITICAL] line 3    win-lsass-dump  Credential dumping via LSASS access  (T1003.001)
[CRITICAL] line 6    win-vss-delete  Volume shadow copy deletion (ransomware precursor)  (T1490)
[HIGH    ] line 1    win-office-shell  Office application spawning a shell  (T1059.003,T1204.002)
...
```

## Writing a rule

```json
{
  "id": "win-vss-delete",
  "title": "Volume shadow copy deletion",
  "level": "critical",
  "tags": ["attack.impact", "attack.t1490"],
  "detection": {
    "vssadmin": {"CommandLine|contains|all": ["vssadmin", "delete", "shadows"]},
    "wmic":     {"CommandLine|contains|all": ["shadowcopy", "delete"]},
    "condition": "vssadmin or wmic"
  }
}
```

Semantics: fields inside a selection are AND-ed, list values are OR-ed
(`|all` makes them AND), and a selection given as a list of mappings is OR-ed.

## Included rules

Encoded PowerShell, LSASS credential dumping, Office spawning shells,
scheduled-task persistence from user-writable paths (excluding SYSTEM),
shadow-copy deletion, and external root SSH logins.

## Tests

```bash
python -m pytest
```

24 tests cover condition parsing/precedence, every modifier, rule validation
failures, a golden test asserting the exact alerts on `samples/events.jsonl`
(including that benign events do **not** fire), severity filtering, and CLI exit codes.

## Design notes

- Conditions are compiled once into a closure over selection results, so
  scanning is a single pass per event per rule.
- Matching is deliberately case-insensitive: Windows paths and command lines
  vary in case, and case games are a classic evasion.
- Limitations: no aggregation/correlation (`count() > N`) or field-mapping layer yet.
