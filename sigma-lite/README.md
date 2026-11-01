# sigmalite

A small **detection-as-code** engine implementing a practical subset of the
[Sigma](https://github.com/SigmaHQ/sigma) rule format. Rules are YAML, events are
JSONL, and every rule carries its own unit tests, so detections can be
reviewed, tested and measured like software.

## Features

- **Condition language**: `and` / `or` / `not`, parentheses, `1 of sel*`, `all of them`
  (recursive-descent parser, short-circuit evaluation, clear errors).
- **Field modifiers**: `contains`, `startswith`, `endswith`, `re`, `all`, `cidr`,
  `lt/lte/gt/gte`; case-insensitive matching, `*`/`?` wildcards, dotted paths into nested events.
- **Rule self-tests**: each rule embeds `match` / `no_match` events. `sigmalite test`
  fails on missed detections, false positives, and rules with no positive test.
- **ATT&CK coverage report** from `attack.tXXXX` tags, flagging untagged rules.
- **Validation**: undefined selections, bad levels, duplicate IDs, malformed conditions and bad JSONL are rejected with file/line context.

## Usage

```bash
pip install -e ".[dev]"
sigmalite scan rules samples/events.jsonl [--min-level high] [--json]   # exit 1 if alerts
sigmalite test rules                                                    # CI gate for rule quality
sigmalite coverage rules [--json]
pytest
```

Example rule (`rules/office_spawns_shell.yml`):

```yaml
title: Office Application Spawning a Shell
id: sl-0003
level: high
tags: [attack.initial_access, attack.t1566.001]
detection:
  parent: {ParentImage|endswith: ['\winword.exe', '\excel.exe']}
  child:  {Image|endswith: ['\cmd.exe', '\powershell.exe']}
  filter_benign: {CommandLine|contains: 'OfficeUpdate'}
  condition: parent and child and not filter_benign
tests:
  match:    [{ParentImage: 'C:\Office\WINWORD.EXE', Image: 'C:\Windows\System32\cmd.exe', CommandLine: 'cmd /c whoami'}]
  no_match: [{ParentImage: 'C:\Windows\explorer.exe', Image: 'C:\Windows\System32\cmd.exe', CommandLine: 'cmd'}]
```

Sample output:

```
[CRITICAL] line 4    LSASS Credential Dumping via comsvcs/procdump (T1003.001)
[HIGH    ] line 1    Office Application Spawning a Shell (T1566.001)
...
```

## Layout

```
sigmalite/  condition.py (parser) · matcher.py (modifiers) · rule.py (load/validate) · engine.py · cli.py
rules/      5 example detections across 5 ATT&CK techniques
samples/    sample JSONL events
tests/      34 pytest tests
```

## Scope / limitations

Not full Sigma: no pipelines/field mapping, `near`/aggregation conditions, or `base64`/`windash`
modifiers. Rules here are illustrative starting points, not production-tuned.
