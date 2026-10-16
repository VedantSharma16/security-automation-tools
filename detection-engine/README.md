# sigmalite: detection-as-code engine

A small, dependency-free detection engine that applies **Sigma-style rules** to JSON event streams.
It treats detections like software: rules are versioned files, carry their own unit tests, are linted
in CI, and map to MITRE ATT&CK so coverage gaps are visible.

## Features

- **Sigma-style matching**: `field|contains|all`, `startswith`, `endswith`, `re`, `cidr`, `gt/gte/lt/lte`, `*`/`?` wildcards, case-insensitive, dotted field paths.
- **Boolean conditions**: `and`, `or`, `not`, parentheses, `1 of sel_*`, `all of them`, parsed by a small recursive-descent parser (no `eval`).
- **Threshold detections**: sliding-window counts grouped by field (e.g. 5 failed SSH logins from one IP in 5 minutes), one alert per group, re-arms when the window drains.
- **Rule unit tests**: every rule embeds `tests.match` / `tests.no_match` events; `sigmalite test` fails CI if a rule regresses.
- **ATT&CK coverage report** from rule tags, listing tactics with no detection.
- **CI-friendly CLI**: `scan --fail-on-alert`, JSON output, strict validation with clear errors and non-zero exits.

## Usage

```bash
python -m sigmalite validate --rules rules/          # lint rules
python -m sigmalite test     --rules rules/          # run embedded rule tests
python -m sigmalite scan     --rules rules/ --events samples/events.jsonl [--format json] [--fail-on-alert]
python -m sigmalite coverage --rules rules/
```

Sample output:

```
[CRITICAL] SL-003 LSASS memory access tool or dump (T1003.001)
[HIGH    ] SL-006 SSH brute force from a single source (T1110.001) x5 {'src_ip': '203.0.113.50'}
...
7 alert(s) from 7 rule(s)
```

## Rule format

```json
{
  "id": "SL-006", "title": "SSH brute force from a single source", "level": "high",
  "tags": ["attack.credential_access", "attack.t1110.001"],
  "detection": { "fail": {"event": "ssh_login", "outcome": "failure"}, "condition": "fail" },
  "threshold": { "count": 5, "timeframe": "5m", "group_by": ["src_ip"] },
  "tests": { "match": [{"event": "ssh_login", "outcome": "failure"}], "no_match": [{"event": "ssh_login", "outcome": "success"}] }
}
```

A selection that is a mapping is AND-ed; a list of mappings is OR-ed; list values on a field are OR-ed unless `|all` is used.

## Shipped rules

Encoded PowerShell (T1059.001), Office spawning shells (T1566.001), LSASS dumping (T1003.001),
scheduled-task persistence (T1053.005), shadow copy deletion (T1490), SSH brute force (T1110.001),
suspicious outbound high-port traffic (T1571).

## Tests

```bash
pip install pytest && pytest
```

34 tests cover the matcher, condition parser (precedence, quantifiers, malformed input), threshold windows,
rule validation, the CLI, and an end-to-end run over the sample events.

## Limitations

- Rules are JSON, not YAML, to stay stdlib-only; the detection block mirrors Sigma semantics but is not a full Sigma converter.
- Coverage maps every technique in a rule to all of that rule's tactic tags (an approximation).
- Threshold events are expected in timestamp order.
