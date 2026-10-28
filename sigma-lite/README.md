# sigmalite

A lightweight, Sigma-compatible detection engine for JSON/JSONL logs. Write
detections as Sigma-style YAML, run them over endpoint or auth telemetry, and
get alerts mapped to MITRE ATT&CK techniques and tactics.

Built to show detection-engineering fundamentals: a real condition-expression
parser (not regex hacks), value modifiers, rule validation, and a CI-friendly CLI.

## Features

- **Sigma-style rules**: `title`, `id`, `level`, `tags` (`attack.t1059.001`), `falsepositives`, `detection`.
- **Modifiers**: `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`; `*`/`?` wildcards on plain matches. Matching is case-insensitive.
- **Conditions**: `and` / `or` / `not`, parentheses, `1 of sel_*`, `all of them`, with proper precedence.
- **Lists**: a value list is OR'd (or AND'd with `|all`); a list of maps is OR'd.
- **Nested fields**: `source.ip` resolves into nested JSON (ECS-style) or flat dotted keys.
- **Validation**: bad levels, malformed ATT&CK tags, unknown selections, invalid regex/CIDR and duplicate rule IDs fail loudly with the file named.
- **CLI**: `scan`, `validate`, `list`; text or JSON output; `--min-level`; `--fail-on <level>` returns exit code 1 for CI/pipelines.

## Usage

```bash
pip install -e '.[dev]'
sigmalite list rules/
sigmalite scan samples/events.jsonl -r rules/ --min-level high
sigmalite scan samples/events.jsonl -r rules/ --format json --fail-on critical
cat events.jsonl | sigmalite scan - -r rules/
pytest
```

Example rule:

```yaml
title: Shadow Copy Deletion
id: sl-0004
level: critical
tags: [attack.impact, attack.t1490]
detection:
  vss:
    CommandLine|contains|all: ['vssadmin', 'delete', 'shadows']
  wmic:
    CommandLine|contains|all: ['wmic', 'shadowcopy', 'delete']
  condition: vss or wmic
```

## Bundled rules

| ID | Detection | ATT&CK |
|---|---|---|
| sl-0001 | Encoded PowerShell | T1059.001 |
| sl-0002 | Office app spawning shell | T1204.002 |
| sl-0003 | LSASS dumping (procdump / comsvcs) | T1003.001 |
| sl-0004 | Shadow copy deletion | T1490 |
| sl-0005 | Scheduled task persistence (with allow-list) | T1053.005 |
| sl-0006 | Privileged login from external IP | T1078 |
| sl-0007 | Download-and-execute cradle | T1105 |

## Layout

```
sigmalite/  condition.py (expression parser)  matcher.py (modifiers)
            rules.py (load/validate)  engine.py (scan/alerts)  cli.py
rules/      example detections      samples/  example telemetry
tests/      pytest suite (19 tests)
```

## Limitations

Implements a practical subset of Sigma: no field-mapping pipelines, `count()`
aggregations/correlation, or `windash`/base64 modifiers yet. Rules are
detection logic only; tune against your environment to manage false positives.
