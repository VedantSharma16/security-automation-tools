# sigma-lite

A small, dependency-light **detection-as-code engine** that runs
[Sigma](https://github.com/SigmaHQ/sigma)-style YAML rules over JSON/JSONL
event logs, tags every alert with MITRE ATT&CK tactics/techniques, and reports
ATT&CK coverage of a rule set. Built to show the blue-team workflow of writing,
linting, testing, and CI-gating detections, not just running scripts.

## Features

- **Sigma-compatible rule format**: `detection` selections, `logsource` category gating, `level`, `tags`, `falsepositives`.
- **Value modifiers**: `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`, plus `*`/`?` wildcards; case-insensitive matching, dotted paths for nested fields, `null` for "field absent".
- **Full condition grammar**: `and` / `or` / `not`, parentheses, `1 of sel_*`, `all of them`, with correct precedence. Invalid conditions fail at load time with clear errors, not at match time.
- **Rule linting** (`validate`): required fields, unknown selections, bad regexes/CIDRs, duplicate IDs.
- **ATT&CK coverage report** (`coverage`) to spot detection gaps.
- **CI gating** (`scan --fail-on-match`, `--min-level`, `--json`) so rules can be regression-tested against known-bad logs.

## Usage

```bash
pip install -r requirements.txt
python -m sigmalite validate rules/
python -m sigmalite scan rules/ samples/events.jsonl --min-level medium
python -m sigmalite coverage rules/
python -m pytest
```

Example output:

```
[CRITICAL] line 3    LSASS Credential Dumping Tooling (T1003.001)
[CRITICAL] line 4    Shadow Copy Deletion (T1490)
[HIGH    ] line 1    PowerShell Encoded Command (T1027,T1059.001)
...
```

## Layout

```
sigmalite/condition.py   condition tokenizer, recursive-descent parser, evaluator
sigmalite/matcher.py     field modifiers, selections, nested field lookup
sigmalite/rule.py        Rule model, YAML loading, validation, ATT&CK tag parsing
sigmalite/engine.py      event scanning, logsource gating, JSONL reader
sigmalite/cli.py         validate / scan / coverage commands
rules/                   6 sample detections (execution, cred access, impact, C2, initial access)
tests/                   26 tests: modifiers, grammar, validation, end-to-end detections, CLI
```

## Scope and limitations

Implements a practical subset of Sigma: no aggregation/`near` conditions, no
field-mapping pipelines (events must already use the field names the rules
expect), and no `windash`/`base64` modifiers. Regexes are length-capped but not
fully ReDoS-proof, so only load rules you trust. Sample events use RFC 5737
documentation IPs.
