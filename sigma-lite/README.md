# sigmalite

A small, dependency-free **Sigma-style detection engine** for JSONL event logs
(EDR/Sysmon-like process events, auth events, etc.) with MITRE ATT&CK reporting.
It demonstrates detection engineering fundamentals: a rule language, a
condition-expression parser, and a CI-friendly scanner.

## Features

- Sigma-layout JSON rules: named selections plus a `condition` expression.
- Value modifiers: `contains`, `startswith`, `endswith`, `re`, `cidr`, `exists`, `all`.
- Case-insensitive matching (as in Sigma), dotted/nested field lookup (`process.parent.name`).
- Condition grammar: `and`/`or`/`not`, parentheses, `1 of sel_*`, `all of them`
  (recursive-descent parser, no `eval`).
- Strict validation: unknown modifiers, bad regexes, unknown selections, and invalid levels are rejected with file-scoped errors.
- ATT&CK technique extraction from `attack.tNNNN[.NNN]` tags and per-technique coverage summary.
- `--fail-on <level>` exit code (2) for use as a CI/pipeline gate; text or JSON output.
- Malformed log lines are counted and skipped, never crash the scan.

## Usage

```bash
pip install -e .[dev]
sigmalite validate rules/
sigmalite scan rules/ samples/events.jsonl --min-level medium
sigmalite scan rules/ samples/events.jsonl --format json --fail-on critical
python -m pytest
```

Sample output on the bundled data:

```
Scanned 8 events (1 malformed lines skipped)
[CRITICAL] line 2    Office application spawning a shell (T1566.001)
[CRITICAL] line 4    Possible LSASS credential dumping (T1003.001)
[HIGH    ] line 3    Encoded PowerShell command line (T1059.001)
[MEDIUM  ] line 5    Scheduled task created via schtasks (T1053.005)
[MEDIUM  ] line 7    SSH login from non-internal address (T1078)
5 alert(s)
```

## Rule example

```json
{
  "id": "SL-004", "title": "SSH login from non-internal address", "level": "medium",
  "tags": ["attack.t1078"],
  "detection": {
    "login":    {"event.action": "ssh_login", "event.outcome": "success"},
    "internal": {"source.ip|cidr": ["10.0.0.0/8", "192.168.0.0/16"]},
    "condition": "login and not internal"
  }
}
```

A selection that is a *map* ANDs its fields; a *list of maps* ORs the maps; a
list of values on one field ORs the values (use `|all` to AND them).

## Layout

```
sigmalite/  condition.py (parser) · matcher.py (modifiers) · rules.py · engine.py · cli.py
rules/      5 example rules mapped to ATT&CK
samples/    sample JSONL events (with one malformed line)
tests/      pytest suite
```

## Design notes / limitations

- Rules are JSON rather than YAML to keep the core stdlib-only; the layout mirrors Sigma so a YAML loader is a small addition.
- Stateless per-event matching; Sigma `count`/`near` aggregation is not implemented.
- Only run it on logs you are authorized to analyze.
