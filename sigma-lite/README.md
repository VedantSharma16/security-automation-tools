# sigma-lite

A lightweight **detection-as-code** engine: write detections as Sigma-style
YAML rules, run them against JSON event logs, lint them in CI, and report
MITRE ATT&CK coverage. Built to show how SOC detection engineering works
under the hood — a rule parser, a condition-expression compiler, and a
modifier-aware field matcher, with no dependency beyond PyYAML.

## Supported Sigma subset

- **Selections**: a map (fields ANDed) or a list of maps (ORed).
- **Value modifiers**: `contains`, `startswith`, `endswith`, `re`, `cidr`,
  `lt`/`lte`/`gt`/`gte`, and `all` (require every listed value).
  Plain equality is case-insensitive and supports `*` / `?` wildcards.
- **Conditions**: `and`, `or`, `not`, parentheses, `1 of sel_*`,
  `all of them` (standard precedence: `not` > `and` > `or`).
- **Logsource filtering** on event fields (e.g. `category: process_creation`).
- **ATT&CK tags** (`attack.t1059.001`) feed the coverage report.
- Nested/dotted field lookup (`Process.Name`), case-insensitive field names.

Not implemented: aggregation (`count() by`), `near` / temporal correlation,
field-mapping pipelines.

## Usage

```bash
pip install -e ".[dev]"

sigmalite validate                                  # lint bundled rules
sigmalite scan samples/events.jsonl                 # run detections
sigmalite scan events.jsonl --min-level high --format json
sigmalite scan events.jsonl --fail-on-match         # exit 1 on alerts (CI gate)
sigmalite coverage                                  # ATT&CK techniques covered
```

Example output on the bundled sample:

```
[CRITICAL] line 3    Credential Dumping via LSASS Access (T1003.001)
[HIGH    ] line 2    PowerShell Encoded Command Execution (T1059.001,T1027)
[HIGH    ] line 2    Office Application Spawning Command Interpreter (T1204.002,T1059)
[HIGH    ] line 5    Certutil Used as Downloader (T1105)
[MEDIUM  ] line 4    Scheduled Task Created from User-Writable Path (T1053.005)
[MEDIUM  ] line 6    Inbound RDP Connection from Public IP (T1133,T1021.001)
```

## Writing a rule

```yaml
title: Certutil Used as Downloader
id: sl-0006
level: high
tags: [attack.command_and_control, attack.t1105]
logsource: {category: process_creation}
detection:
  tool:  {Image|endswith: '\certutil.exe'}
  fetch: {CommandLine|contains: ['urlcache', 'verifyctl']}
  url:   {CommandLine|re: 'https?://'}
  condition: tool and 1 of fetch* and url
```

Validation rejects missing IDs, bad levels, unknown modifiers, invalid
regex/CIDR, conditions that reference undefined selections, and duplicate
rule IDs — so a broken rule fails CI instead of silently never firing.

## Layout

```
sigmalite/condition.py   recursive-descent condition parser/evaluator
sigmalite/matcher.py     field lookup + modifier predicates
sigmalite/rule.py        rule model, validation, loading
sigmalite/engine.py      JSONL reader, scanning, coverage
sigmalite/cli.py         validate / scan / coverage
rules/                   6 bundled rules (LSASS dump, encoded PS, macro spawn, ...)
samples/events.jsonl     benign + malicious sample telemetry
```

## Tests

```bash
pytest        # 35 tests: modifiers, condition grammar, validation, end-to-end, CLI
```

Detections are only as good as their tests: the suite asserts the exact set
of (rule, event) pairs that fire on the sample data, including a negative
case (private-IP RDP must not alert).

Rules are written for defensive detection engineering and ship with
synthetic sample telemetry only.
