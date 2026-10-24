# sigma-lite

A lightweight **detection-as-code** engine that evaluates Sigma-style YAML rules
against JSON event logs, with built-in rule unit tests and MITRE ATT&CK
coverage reporting. Detection engineering is treated like software: every rule
ships with its own `match` / `no_match` test cases that CI can run.

## Features

- Sigma-compatible rule format: named selections, lists (OR), maps (AND), `|contains`, `|startswith`, `|endswith`, `|re`, `|cidr`, `|gt/gte/lt/lte`, `|all`, and `*`/`?` wildcards
- Full condition grammar: `and` / `or` / `not`, parentheses, `1 of sel*`, `all of them`
- Strict validation: unknown selections, bad regex/CIDR, unsupported modifiers and duplicate rule IDs are rejected at load time
- Rule self-tests (`sigmalite test`): each rule must include at least one positive and one negative case
- ATT&CK coverage map (`sigmalite coverage`) built from rule tags
- Scan JSONL from a file or stdin, filter by severity, emit human or JSON output

## Usage

```bash
pip install -r requirements.txt
python -m sigmalite validate
python -m sigmalite test
python -m sigmalite coverage
python -m sigmalite scan samples/events.jsonl --min-level high
```

`scan` exits `1` when alerts fire (handy in pipelines), `2` on bad input.

## Rule example

```yaml
title: LSASS Credential Dumping Tools
id: sl-0004
level: critical
tags: [attack.credential_access, attack.t1003.001]
detection:
  procdump:
    CommandLine|contains|all: ['procdump', 'lsass']
  mimikatz:
    CommandLine|contains: ['sekurlsa::', 'mimikatz']
  condition: 1 of them
tests:
  match:    [{CommandLine: 'procdump.exe -ma lsass.exe out.dmp'}]
  no_match: [{CommandLine: 'procdump.exe -ma notepad.exe out.dmp'}]
```

## Layout

```
sigmalite/   condition.py (parser) · matchers.py · rule.py · engine.py · cli.py
rules/       5 sample rules (PowerShell, macro child procs, SSH, LSASS, local admin)
samples/     example event stream
tests/       pytest suite
```

## Tests

```bash
pip install -r requirements.txt && pytest
```

## Scope

Not a full Sigma implementation: no aggregation (`count() by`), no field
mapping pipelines, and no `near` / temporal conditions. Matching is
case-insensitive, as in Sigma.
