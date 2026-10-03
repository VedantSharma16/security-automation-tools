# sigmalite

A lightweight, dependency-light **Sigma-compatible detection engine** for JSON/JSONL
event streams. It compiles community-style [Sigma](https://sigmahq.io) YAML rules and
runs them against logs (Sysmon/EDR exports, auth logs, network telemetry) with ATT&CK
tagging, severity filtering and CI-friendly exit codes.

Built to show detection-engineering fundamentals: how a rule language is parsed,
compiled and evaluated, rather than gluing together an existing library.

## Features

- **Field modifiers:** `contains`, `startswith`, `endswith`, `re`, `cidr`, `gt/gte/lt/lte`, plus `all` and `cased` flags
- **Sigma matching semantics:** case-insensitive by default, `*`/`?` wildcards with `\` escapes, `null` for missing fields, dotted nested-field lookup
- **Selections:** maps (AND), lists of maps (OR), keyword lists, list-valued event fields
- **Condition grammar:** recursive-descent parser with `and`/`or`/`not` precedence, parentheses, `1 of sel_*`, `all of them`; lazy short-circuit evaluation; multiple conditions OR-ed
- **Strict validation:** unknown selections, bad modifiers, empty selections, invalid levels and malformed conditions are rejected at load time, not at match time
- **ATT&CK extraction** from `attack.tNNNN[.NNN]` tags in text and JSON output

## Usage

```bash
pip install -e ".[dev]"

sigmalite validate rules/
sigmalite scan rules/ sample_events.jsonl
sigmalite scan rules/ sample_events.jsonl --min-level high --format json
cat events.jsonl | sigmalite scan rules/ - --fail-on-match   # exit 1 on detection (CI/pipelines)
```

Example output:

```
[HIGH    ] event #0  Suspicious Encoded PowerShell Command  (ATT&CK: T1059.001,T1027)
[HIGH    ] event #1  Office Application Spawns Command Interpreter  (ATT&CK: T1566.001,T1204.002)
[CRITICAL] event #2  Credential Dumping via comsvcs or procdump on LSASS  (ATT&CK: T1003.001)
[MEDIUM  ] event #4  Successful Privileged SSH Login From External Address  (ATT&CK: T1078,T1021.004)
[LOW     ] event #7  Outbound Connection To Metasploit Default Port  (ATT&CK: T1571)

8 events, 6 rules, 5 detections (1 critical, 2 high, 1 medium, 1 low)
```

Exit codes: `0` ok, `1` detections found with `--fail-on-match`, `2` error (bad rule, bad input).

## Bundled rules (`rules/`)

| Rule | Level | ATT&CK |
|---|---|---|
| Encoded PowerShell / download cradles | high | T1059.001, T1027 |
| Office app spawning a shell | high | T1566.001, T1204.002 |
| LSASS dump via comsvcs / procdump | critical | T1003.001 |
| External privileged SSH login (CIDR exclusion) | medium | T1078, T1021.004 |
| Scheduled task from user-writable path (with filter) | medium | T1053.005 |
| Connection to TCP 4444 (numeric + nested fields) | low | T1571 |

## Layout

```
sigmalite/
  matchers.py   field modifiers and value matching
  condition.py  condition tokenizer, parser (AST), lazy evaluator
  rules.py      YAML loading, validation, selection compilation
  engine.py     scan loop, JSONL reader, Match results
  cli.py        validate / scan commands
rules/          example detections
tests/          pytest suite (36 tests)
```

## Tests

```bash
pytest
```

## Scope and limitations

Implements the commonly used core of the Sigma spec. Not supported: `near`/`count`
aggregations and temporal correlation, field-name mapping pipelines (backends), and
value modifiers such as `base64`, `windash` or `utf16`. Unsupported modifiers fail
loudly at load time instead of silently never matching.
