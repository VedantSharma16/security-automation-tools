# sigma-lite

A small, dependency-light **Sigma-compatible detection engine**. It loads
standard Sigma YAML rules, evaluates them against JSONL event streams (Sysmon,
EDR, or network telemetry exported as JSON), and reports alerts with MITRE
ATT&CK technique/tactic context.

Built to show detection-engineering fundamentals: how a rule language compiles
down to matching logic, rather than just calling a library.

## Features

- **Field modifiers:** `contains`, `startswith`, `endswith`, `re`, `cidr`,
  `lt/lte/gt/gte`, and `all`; plain values support `*`/`?` wildcards and are
  case-insensitive, as in Sigma.
- **Condition language:** recursive-descent parser for `and` / `or` / `not`,
  parentheses, `1 of sel*`, `all of them`; list conditions are OR'd.
- **Selections:** maps (AND across fields) and lists of maps (OR).
- **Fields:** case-insensitive lookup, dotted paths into nested JSON, null matching.
- **ATT&CK:** techniques/tactics parsed from `attack.*` tags and summarised.
- **Safety:** rules are loaded with `yaml.safe_load`; regexes are length-capped
  and compiled up front; invalid rules fail loudly with file and title.
- **CLI exit codes:** `0` no alerts, `1` alerts, `2` error, so it drops into CI/pipelines.

## Usage

```bash
pip install -e .[dev]
sigmalite --rules rules/ --events tests/fixtures/events.jsonl
sigmalite --rules rules/ --events events.jsonl --min-level high --format json
cat events.jsonl | sigmalite --rules rules/ --events -
```

```
[HIGH    ] line 1: Encoded PowerShell Command (T1059.001,T1027)
[CRITICAL] line 2: Office Application Spawning Shell (T1566.001,T1204.002)
...
5 rules, 5 alert(s) | techniques: T1059.001, T1027, ...
```

## Included rules

| Rule | Level | ATT&CK |
|---|---|---|
| Encoded PowerShell Command | high | T1059.001, T1027 |
| Office Application Spawning Shell | critical | T1566.001, T1204.002 |
| Credential Dumping via comsvcs MiniDump | critical | T1003.001 |
| Inbound RDP From Public Address | medium | T1021.001 |
| Certutil Used As Downloader | high | T1105 |

## Layout

```
sigmalite/  matchers.py (modifiers) · condition.py (parser) · rules.py · engine.py · cli.py
rules/      example Sigma rules
tests/      pytest suite (32 tests) + JSONL fixture
```

## Scope and limits

Implements the commonly used subset of Sigma. Not supported: aggregation
(`count() > N`), `timeframe`/correlation rules, `base64`/`windash` modifiers,
and logsource-based field mapping. Rules are evaluated per event.

## Tests

```bash
pytest
```
