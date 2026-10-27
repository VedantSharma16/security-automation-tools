# sigmalite — detection-as-code rule engine

A small, dependency-free, Sigma-inspired detection engine. Write detections as
JSON rules, lint them in CI, run them over JSONL event streams, and report
MITRE ATT&CK coverage. Built to show how detection engineering works under the
hood: a **safe condition parser** (no `eval`), **field modifiers**, and
**load-time rule validation**.

## Quick start

```bash
pip install -e ".[dev]"
sigmalite validate rules/                       # lint rules (CI-friendly)
sigmalite scan rules/ samples/events.jsonl      # exit 1 if anything matches
sigmalite scan rules/ samples/events.jsonl --min-level high --json
sigmalite coverage rules/                       # ATT&CK technique -> rule ids
pytest
```

Exit codes: `0` clean, `1` detections found, `2` bad rules/input.

## Rule format

```json
{
  "id": "SL-0002",
  "title": "Office Application Spawning a Shell",
  "level": "critical",
  "tags": ["attack.initial_access", "attack.t1566.001"],
  "detection": {
    "parent": {"ParentImage|endswith": ["\\winword.exe", "\\excel.exe"]},
    "child":  {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"]},
    "condition": "parent and child"
  }
}
```

- A selection is an **AND** of its fields; a list of values for one field is an **OR** (use `|all` to AND them).
- Modifiers: `contains`, `startswith`, `endswith`, `re`, `cidr`, `gt/gte/lt/lte`, `all`. Matching is case-insensitive; dotted field names reach into nested events.
- Conditions: `and`, `or`, `not`, parentheses, `1 of sel*`, `all of them`.
- Techniques are read from `attack.tNNNN[.NNN]` tags.

## Design notes

- **Conditions are parsed, not evaluated.** A recursive-descent parser builds an AST, so a rule file can never execute code.
- **Fail early.** Unknown selections, empty globs, bad regexes/CIDRs, unknown modifiers, duplicate ids, and invalid levels are rejected when rules load. Regex length is capped.
- **Tolerant ingest.** Malformed JSONL lines are skipped rather than aborting a scan.
- Rules are plain JSON to keep the core stdlib-only; a YAML front-end would be a thin loader on top of `parse_rule`.

## Layout

```
sigmalite/  condition.py (parser/AST)  matchers.py (modifiers)  rules.py  engine.py  cli.py
rules/      5 example detections (encoded PowerShell, macro shells, LSASS dump, external RDP, certutil)
samples/    mixed benign/malicious event stream
tests/      37 tests
```
