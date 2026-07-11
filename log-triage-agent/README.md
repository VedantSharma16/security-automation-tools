# Log Triage Agent

A small blue-team tool that parses SSH authentication logs, detects
suspicious login activity, maps each detection to the relevant
[MITRE ATT&CK](https://attack.mitre.org/) technique via a local retrieval
step, and generates an analyst-readable Markdown incident report — with an
optional LLM-generated narrative on top.

It's built to show one thing in particular: a **retrieval-augmented
generation pipeline applied to an actual security use case** (log triage),
rather than a toy RAG-over-PDFs demo. The retrieval and generation layers
are cleanly separated so either one can be swapped out independently.

```
parse (auth.log) -> detect (rules)  -> retrieve (ATT&CK KB) -> generate (report)
   parsers.py        detectors.py       knowledge_base.py       reporter.py
```

## Why this exists

Password spraying, brute forcing, and "give up and switch to a stolen
credential" are common enough patterns that a SOC analyst can eyeball them
in a log — but at scale, someone (or something) has to do the first pass.
This tool automates that first pass: it turns a raw log into a triaged,
prioritized, technique-mapped report in one command, with recommended
response actions attached to each finding.

## What it detects

| Detector | Signal | ATT&CK mapping |
|---|---|---|
| Brute force | N+ failed logins from one IP in a rolling window | T1110, T1110.001 |
| Password spray | One IP tries many distinct usernames in a window | T1110.003 |
| Credential success after failures | A login succeeds shortly after several failures from the same IP | T1078, T1021.004 |
| Off-hours login | A successful login lands outside business hours | Behavioral indicator, T1021.004 |

Detectors are independent, pure functions over a list of parsed events —
each is unit tested in isolation (`tests/test_detectors.py`) and composed
by `run_all_detectors()`.

## Retrieval + generation

`knowledge_base.py` holds a small local JSON knowledge base of ATT&CK
techniques (`data/attack_techniques.json`) and retrieves the most relevant
ones for a given finding using token-overlap (Jaccard) scoring — no
embeddings or vector DB needed to demonstrate the retrieval pattern at this
scale.

`reporter.py` then generates the narrative for each finding:

- **`TemplateNarrator`** — fully offline, deterministic, zero dependencies.
  This is the default and requires no setup at all.
- **`AnthropicNarrator`** — optional. If the `anthropic` package is
  installed and `ANTHROPIC_API_KEY` is set, the reporter asks Claude to
  turn the retrieved ATT&CK context + finding into a short analyst
  narrative. Any failure (no key, no package, network error) transparently
  falls back to the template narrator, so the tool never breaks because of
  the optional enrichment step.

This mirrors a production RAG pipeline: retrieval grounds the generation
step in real facts (the actual detection + real ATT&CK descriptions),
rather than letting a model free-associate about "what a brute force
attack probably looks like."

## Usage

No installation required to run the core pipeline:

```bash
cd log-triage-agent
python3 -m log_triage_agent --log data/sample_auth.log --year 2026
```

Write the report to a file instead of stdout:

```bash
python3 -m log_triage_agent --log data/sample_auth.log --year 2026 --out report.md
```

`--year` is needed because syslog-style timestamps (`Jul 10 02:10:01`)
don't include a year; omit it to default to the current year, which is
what you want for a live log.

To enable the optional LLM narrative:

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
python3 -m log_triage_agent --log data/sample_auth.log --year 2026
```

## Sample data

`data/sample_auth.log` is a synthetic log (no real hosts, IPs, or
credentials) modeling a realistic attack chain: an external IP password
sprays a handful of usernames, crosses the brute-force threshold, and then
succeeds against `root` at 2am — plus some benign traffic that should
*not* trigger any finding, to sanity-check against false positives.

## Running the tests

Stdlib `unittest` only — no `pytest` install required:

```bash
cd log-triage-agent
python3 -m unittest discover -s tests -v
```

31 tests cover the parser (valid/invalid lines, malformed input), each
detector (both the trigger and non-trigger cases, including window-boundary
edge cases), the knowledge base retrieval/ranking, the report generator
(severity ordering, empty-findings case), and an end-to-end CLI run against
the sample log.

## Design notes / extending this

- **Swap the retriever**: `AttackKnowledgeBase._score` is the only place
  that knows about Jaccard similarity. Replace it with an embedding lookup
  (e.g. a small local sentence-transformer or a vector DB) without touching
  `detectors.py` or `reporter.py`.
- **Swap the generator**: `reporter.py`'s narrators share one interface
  (`narrate(finding, techniques) -> str`). Adding an OpenAI- or
  local-model-backed narrator is a new class, not a rewrite.
- **Add a detector**: any function `(events: list[LogEvent]) -> list[Finding]`
  can be added to `DEFAULT_DETECTORS` in `detectors.py`.
- **Add a log source**: `parsers.py` only knows about OpenSSH syslog lines
  today; a Windows Security Event log or cloud IAM sign-in log parser would
  plug into the same `LogEvent` model.

This is a defensive/blue-team tool intended for training and portfolio
purposes, operating only on synthetic log data included in this repo.
