# vuln-prioritizer

A command-line tool that turns a raw vulnerability scan export into a
ranked, defensible patch-priority list — the part of vulnerability
management that "just sort by CVSS" gets wrong.

## Why CVSS alone isn't enough

CVSS measures theoretical severity: how bad a vulnerability *could* be if
exploited. It says nothing about whether anyone is actually exploiting it,
or whether the affected asset matters to the business. Sorting a scan
report by CVSS descending routinely buries actively-exploited vulnerabilities
under theoretical-but-unexploited "10.0" findings on low-value hosts —
a well-documented failure mode in real vulnerability management programs.

This tool scores each finding on four independent signals and combines
them into one auditable 0-100 priority score:

| Signal | Source | What it captures |
|---|---|---|
| CVSS base score | The scan export itself | Technical severity if exploited |
| EPSS | [FIRST.org's Exploit Prediction Scoring System](https://www.first.org/epss/) | Probability of exploitation in the next 30 days |
| CISA KEV | [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed, *ongoing* exploitation in the wild |
| Asset criticality / exposure | A local asset inventory | Business impact and internet-facing exposure |

```
priority_score = min(100, base * criticality_weight * exposure_multiplier)
base           = 0.40 * (cvss_score * 10)     # 0-40
                + 0.35 * (epss_score * 100)    # 0-35
                + 25 if CVE is in CISA KEV else 0
```

The result: a medium-CVSS vulnerability with confirmed active exploitation
on an internet-facing, business-critical host can — correctly — outrank a
higher-CVSS finding on an isolated, low-value host. Every score comes with
a `rationale` list explaining exactly which factors drove it, so the
output is reviewable, not a black box.

`data/kev_catalog_sample.json` and `data/epss_scores_sample.json` are small,
hand-curated snapshots bundled for offline use and testing — not a live
feed sync. Point `--kev` / `--epss` at downloaded copies of the real feeds
for production use.

## Install

```bash
cd vuln-prioritizer
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered executive narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
vulnprioritize scan scan_export.csv
vulnprioritize scan scan_export.csv --assets assets.json
vulnprioritize scan scan_export.csv --assets assets.json --format json --out report.json
vulnprioritize scan scan_export.csv --assets assets.json --top 10       # top 10 in the Markdown report
vulnprioritize scan scan_export.csv --assets assets.json --llm          # Claude-written executive summary
```

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic, offline template narrator — the tool is always usable
without any API key or network access.

Try it against the bundled example:

```bash
vulnprioritize scan examples/sample_scan.csv --assets examples/sample_assets.json
```

### Scan export format

A CSV with (at minimum) a host column and, ideally, `cve_id` and
`cvss_score` columns. Common scanner column-name variants are accepted
(`host`/`hostname`/`asset`, `cve`/`cve_id`, `cvss`/`cvss_score`, etc. — see
`vuln_prioritizer/ingest.py` for the full alias list). A row without a CVE
is still scored on CVSS/asset context alone; it just skips EPSS/KEV
enrichment.

### Asset inventory format

A JSON list, e.g.:

```json
[
  { "hostname": "web01.example.com", "criticality": "critical", "internet_facing": true, "tags": ["public-web"] }
]
```

`criticality` is one of `critical` / `high` / `medium` / `low`. Hosts not
listed default to `medium` criticality, not internet-facing.

## Architecture

```
vuln_prioritizer/
  ingest.py            scan CSV -> Finding (tolerant of scanner column-naming variants)
  asset_inventory.py    asset JSON -> Asset (criticality, internet-facing), with a safe default
  enrichment.py         CVE -> EPSS score + CISA KEV status, from bundled local data
  scoring.py            Finding + Asset + Enrichment -> ScoredFinding (score, tier, rationale)
  pipeline.py            wires ingest -> asset lookup -> enrichment -> scoring
  report.py             ScoredFinding list -> structured report -> Markdown / JSON
  llm_narrative.py      structured report -> executive narrative (template, or optional Claude)
  cli.py                argument parsing and orchestration
```

Each stage takes and returns plain dataclasses/dicts, so the pipeline is
usable as a library (`from vuln_prioritizer.pipeline import prioritize`)
as easily as from the CLI.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

55 tests cover CSV parsing (including malformed input and column-name
aliases), asset inventory loading, enrichment lookups, the scoring formula
(including the "medium-CVSS-but-actively-exploited beats high-CVSS-
theoretical" case the tool exists to fix), report rendering, the narrator
fallback chain, and the CLI end-to-end. Everything runs offline — no
network calls, no API key required.
