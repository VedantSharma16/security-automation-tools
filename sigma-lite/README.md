# sigma-lite

A small **detection-as-code** engine in the style of [Sigma](https://sigmahq.io): write detection rules as data, lint them, replay event logs against them, and measure MITRE ATT&CK coverage. Stdlib-only core.

Why it exists: blue teams ship detections like software. This project shows the full loop - author, lint, test, gate in CI - and the engine internals (a real condition-expression parser, not regex tricks).

## Features

- **Sigma-style matching**: `field|contains`, `startswith`, `endswith`, `re`, `cidr`, `lt/lte/gt/gte`, `|all`, `*`/`?` wildcards, dotted nested fields, case-insensitive by default.
- **Condition language** via a recursive-descent parser: `and`/`or`/`not`, parentheses, `1 of sel*`, `all of them`, with correct precedence.
- **Rule linter**: undefined/unused selections, unknown modifiers, malformed ATT&CK tags, bad severity, duplicate IDs - fails before a bad rule reaches production.
- **Replay** JSONL events, with summary and `--fail-on-match` exit code for CI gating.
- **ATT&CK coverage** report from rule tags.
- Rules in JSON by default; `.yml/.yaml` supported with `pip install pyyaml`.

## Usage

```bash
pip install -e .[dev]
sigmalite validate rules/
sigmalite run rules/ examples/events.jsonl          # human output
sigmalite run rules/ examples/events.jsonl --json   # machine output
sigmalite coverage rules/
pytest
```

Example rule:

```json
{"id": "SL-004", "title": "Volume shadow copy deletion", "level": "high",
 "tags": ["attack.impact", "attack.t1490"],
 "detection": {
   "vss": {"CommandLine|contains": ["vssadmin delete shadows", "wmic shadowcopy delete"]},
   "bcd": {"CommandLine|contains|all": ["bcdedit", "recoveryenabled", "no"]},
   "condition": "vss or bcd"}}
```

The bundled `examples/events.jsonl` simulates an intrusion chain (macro -> encoded PowerShell -> persistence -> LSASS dump -> external RDP -> shadow copy deletion); all six bundled rules fire while benign and internal-RDP events do not.

## Layout

```
sigmalite/condition.py  condition parser + evaluator
sigmalite/matcher.py    field modifiers and selection matching
sigmalite/rules.py      loading, linting, Rule model
sigmalite/engine.py     replay, summary, coverage
sigmalite/cli.py        validate | run | coverage
rules/  examples/  tests/
```

## Limitations

No Sigma `count()`/`near` aggregation, field-mapping pipelines or backend conversion (Splunk/Elastic) yet - natural next steps.
