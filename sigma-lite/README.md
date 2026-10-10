# sigma-lite

A dependency-free **Sigma rule engine** for detection-as-code: load Sigma-style
YAML rules, evaluate them against JSON event streams, lint conditions, and
report **MITRE ATT&CK coverage** with gap analysis. Built to show how detection
engineering works under the hood rather than wrapping an existing library.

## Features

- **Own YAML-subset parser** (`yamlmini.py`) – no PyYAML; unsupported constructs
  (anchors, block scalars, duplicate keys, tab indentation) fail loudly instead of
  being misparsed.
- **Field modifiers**: `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`,
  `gt/gte/lt/lte`, `base64`, `exists`; case-insensitive matching with `*`/`?`
  wildcards (and `\*` escapes); dotted access into nested events.
- **Condition language** via a recursive-descent parser: `and`/`or`/`not`,
  parentheses, `1 of sel_*`, `all of them`. Unknown selections or empty globs are
  caught at load time.
- **Safe by construction**: regexes are length-capped, selections are only
  data (no code execution).
- **ATT&CK coverage**: technique/tactic rollup from `attack.*` tags, untagged-rule
  detection, and `--wanted` gap analysis (a sub-technique covers its parent).
- **CI-friendly CLI**: `scan` exits `1` on any match, `2` on errors.

## Usage

```bash
python -m sigmalite validate rules/
python -m sigmalite scan rules/ samples/events.jsonl          # text
python -m sigmalite scan rules/ samples/events.jsonl --json   # machine-readable
python -m sigmalite coverage rules/ --wanted T1059 T1003 T1021
```

Sample output:

```
[HIGH    ] Encoded PowerShell Command (event #0, T1059.001,T1027)
[CRITICAL] Office Application Spawning Shell (event #2, T1566.001,T1204.002)
[CRITICAL] LSASS Credential Dumping Tool (event #3, T1003.001)
[MEDIUM  ] Failed Login From Public Range (event #4, T1110)
4 match(es) across 4 rule(s)
```

Note the allow-listed SCCM PowerShell event (#1) and the internal-IP failed login
(#5) are correctly suppressed by `not filter` / `not internal` clauses.

## Layout

```
sigmalite/   yamlmini.py  rule.py  matcher.py  condition.py  engine.py  coverage.py  cli.py
rules/       4 example rules tagged with ATT&CK techniques
samples/     events.jsonl – mixed malicious/benign events
tests/       29 pytest tests (parser, modifiers, conditions, engine, CLI)
```

## Tests

```bash
pip install pytest && python -m pytest -q
```

## Limitations

Supports a practical subset of Sigma: single-document rules, no `timeframe` /
aggregation (`count() > N`) or correlation rules, no backend conversion (Splunk,
Elastic). Logsource is recorded but not used to filter events.
