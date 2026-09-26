# sigma-rule-tuner

A command-line tool that automatically tunes MITRE ATT&CK-mapped Sigma
detection rules against labeled sample telemetry, instead of asking a human
(or an LLM) to guess the right thresholds and exclusion filters up front.

Detection engineering is normally an iterative, evidence-driven process: an
analyst writes a broad rule, runs it against real data, sees it's noisy or
too narrow, and narrows or widens it — repeating until precision and recall
both look acceptable. This tool automates that loop:

1. A small **knowledge base** (`data/technique_kb.json`) holds, per ATT&CK
   technique, an ordered list of rule *variants* — the same candidates a
   detection engineer would try, from broadest ("any auth failure") to most
   specific ("burst threshold + internal-IP exclusion").
2. A **plan-act-observe loop** (`sigma_tuner/tuner.py`) walks that list: it
   builds a full Sigma-style rule for each variant, evaluates it against a
   labeled event set, and stops as soon as one meets configurable
   precision/recall thresholds — or falls back to the best-scoring variant
   if none do.
3. An **LLM narrator** (optional, `--llm`) writes the analyst-facing
   rationale afterwards — it never sees raw events and cannot change the
   selected rule's logic, it only explains a decision that's already been
   made deterministically.

This mirrors the design philosophy used elsewhere in this repo
(`log-triage-assistant`, `recon-agent`): **the decision that matters stays
deterministic and auditable; the LLM is confined to writing prose on top of
evidence it didn't get to interpret.**

## Why this is a different shape of tool

The other projects in this repo *consume* logs/alerts/processes and tell you
whether something bad already happened. This one *produces* the detection
content used to catch it next time, and — because it scores every candidate
rule against ground truth before recommending one — it can show its work:
which rule would have been too noisy, which would have missed the attack,
and why the one it picked is the first to clear both bars.

## Install

```bash
cd sigma-rule-tuner
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered analyst narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
sigma-tuner list-techniques

sigma-tuner tune --technique T1110 --events examples/t1110_ssh_bruteforce.jsonl
sigma-tuner tune --technique T1003.001 --events examples/t1003.001_credential_dumping.jsonl --format markdown
sigma-tuner tune --technique T1110 --events examples/t1110_ssh_bruteforce.jsonl --format yaml --out rule.yml
sigma-tuner tune --technique T1110 --events examples/t1110_ssh_bruteforce.jsonl --llm  # Claude-written analyst notes
```

`--format` is `json` (default, full report), `markdown` (report + embedded
YAML rule, readable in a PR or ticket), or `yaml` (just the final Sigma
rule, ready to drop into a detection repo). The exit code is `0` if tuning
converged (met both thresholds) and `1` if it didn't — so it's usable as a
CI gate on a detection-content pipeline.

### Example: watching the search actually work

```bash
sigma-tuner tune --technique T1110 --events examples/t1110_ssh_bruteforce.jsonl --format markdown
```

produces a trace like:

| Variant | Precision | Recall | F1 | Rationale |
|---|---|---|---|---|
| `v1_any_failure` | 0.6 | 1.0 | 0.75 | Any auth failure — catches everything, including typos. |
| `v2_burst_threshold` | 0.57 | 0.33 | 0.42 | Threshold >=5 failures/5min — *worse* precision, because an internal monitoring script also bursts. |
| `v3_exclude_internal` | 1.0 | 0.33 | 0.5 | Exclude RFC1918 sources — precision fixed, recall still low. |
| `v4_lower_threshold_3` | 1.0 | 0.67 | 0.8 | Lower threshold to >=3 to catch the campaign earlier. |
| `v5_lower_threshold_2` | 1.0 | 0.83 | 0.91 | Lower to >=2 — **converged**. |

Note that `v2` is *worse* than `v1` on precision — raising a threshold isn't
automatically an improvement if it doesn't address the actual source of
false positives. That's a real, common detection-engineering trap, and the
tuning trace shows it happening instead of hiding it.

## Architecture

```
sigma_tuner/
  dsl.py            Sigma-subset field/block/condition evaluator (no eval(); an AST-restricted safe parser)
  technique_kb.py    Loads data/technique_kb.json (ATT&CK ID -> ordered rule variants)
  rule_builder.py    technique + variant -> a full Sigma-style rule dict
  evaluator.py       rule + labeled events -> precision/recall/F1 confusion-matrix metrics
  tuner.py           the plan-act-observe search loop over a technique's variants
  narrative.py       TemplateNarrator (offline) / AnthropicNarrator (--llm) write-up of the result
  report.py          bundles a TuningResult into JSON / Markdown output
  yaml_dump.py       tiny dependency-free YAML serializer for the final rule
  cli.py             argparse entry point wiring the above together
```

Each stage only depends on the previous stage's output, so every piece is
independently unit-tested — see `tests/`, which locks in the exact
precision/recall trajectory on both bundled fixtures (so a change to the
DSL or the KB that breaks the tuning story fails a test, not just a vibe
check).

## The Sigma subset this implements

Real Sigma (https://github.com/SigmaHQ/sigma-specification) targets a wide
range of backends (Splunk, Elasticsearch, ...) and includes aggregation
(`count() by ... > N`) that requires a query engine, not just per-event
evaluation. This project implements a deliberately smaller subset that's
enough to be genuinely useful and testable in pure Python:

- Field modifiers: plain equality/membership, `contains`, `startswith`,
  `endswith`, `re`, and `gte`/`lte`/`gt`/`lt` (a documented **extension**
  beyond the spec, for pre-aggregated fields like `failed_attempts_5m` that
  a SIEM has already computed).
- A block (`selection`, `filter`, ...) is an AND of its fields; a field
  given a list of values is an OR across that list.
- A `condition` string combines block names with `and` / `or` / `not` /
  parentheses — evaluated via a restricted `ast` walk, never `eval()`, so a
  malformed or adversarial condition string can raise but never execute
  code.

A rule built by this tool is valid, readable Sigma YAML and can be handed to
a real Sigma converter for backend-specific deployment; this project's own
evaluator exists so the *tuning* step doesn't need a live SIEM to run
against.

## Knowledge base and sample data

`data/technique_kb.json` currently covers two techniques chosen to show the
approach generalizes across log domains:

- **T1110 (Brute Force)** — SSH auth-failure events, tuned via a burst
  threshold plus an internal-IP exclusion filter (`examples/t1110_ssh_bruteforce.jsonl`,
  20 labeled events).
- **T1003.001 (OS Credential Dumping: LSASS Memory)** — Windows
  process-creation events, tuned by replacing a naive `contains "lsass"`
  keyword rule with named indicators for procdump/mimikatz plus the
  `comsvcs.dll` MiniDump LOLBin technique, which a keyword search both
  misses (it doesn't mention "lsass") and false-positives on (EDR tools
  that do) (`examples/t1003.001_credential_dumping.jsonl`, 8 labeled events).

Labels (`"label": true/false` per event) represent ground truth a human
analyst would supply after confirming an incident — in production these
would come from a purple-team exercise or confirmed IR tickets, not from
the detection rule itself. Adding a new technique means adding a KB entry
plus a small labeled fixture; nothing else in the pipeline needs to change.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

61 tests cover the DSL (including that the condition parser genuinely can't
execute arbitrary code), the KB loader, rule assembly (including that KB
data isn't mutated across builds), the metrics evaluator, the exact tuning
trajectory on both fixtures, the narrators, the YAML serializer, and the CLI
end-to-end.

## Why this design

Detection-as-code pipelines increasingly want rules backed by evidence, not
intuition — a rule that's never been run against real telemetry is a guess.
Making the search loop deterministic (rather than having an LLM propose
thresholds) keeps every recommendation reproducible and reviewable: given
the same KB and the same labeled events, this tool always produces the same
rule, and the tuning trace is a ready-made justification for why that rule
— and not the simpler one someone will inevitably suggest in review — is
the one that shipped.
