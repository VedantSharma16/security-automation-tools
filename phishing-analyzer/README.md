# phishscan

A static, fully offline phishing-email (`.eml`) analyzer for SOC triage. It
never fetches URLs or opens attachments — it inspects headers, links,
attachment metadata and wording, then produces an explainable 0–100 verdict
where every finding carries evidence and a MITRE ATT&CK technique ID.

## What it checks

| Analyzer | Indicators |
|---|---|
| Headers | SPF/DKIM/DMARC fail or missing, Reply-To / Return-Path domain mismatch, brand impersonation in display name |
| URLs | raw-IP hosts, URL shorteners, punycode/homograph domains, `user@host` tricks, brand look-alike domains, abused TLDs, **visible link text vs. real href mismatch** |
| Attachments | double extensions (`invoice.pdf.exe`), executables/scripts, macro-enabled Office files, archives |
| Content | urgency/pressure language, credential-harvesting lures |

Each rule counts once toward the score (so 20 shortened links don't swamp the
verdict). Labels: `CLEAN` < 15 ≤ `LOW_RISK` < 40 ≤ `SUSPICIOUS` < 70 ≤ `MALICIOUS`.

## Usage

```bash
pip install -e ".[dev]"
phishscan tests/fixtures/phish.eml                    # Markdown report
phishscan suspicious.eml --format json                # machine-readable
phishscan suspicious.eml --fail-on 70                 # exit code 2 if score >= 70 (mail-gateway/CI hook)
```

## Layout

```
phishscan/
  parser.py      raw RFC 5322 -> ParsedEmail (headers, links incl. anchor text, attachments)
  analyzers.py   four independent rule sets -> Finding(rule, severity, evidence, ATT&CK id)
  scoring.py     findings -> deduplicated weighted score + label
  report.py      Markdown / JSON rendering
  cli.py         argparse entry point
```

Stdlib-only. Tests (`pytest -q`) cover the parser, each rule family, scoring
thresholds and the CLI, using a synthetic phishing sample and a benign one.

## Limitations

Heuristic, not a replacement for sandbox detonation or threat-intel lookups.
Authentication results are read from the receiving server's
`Authentication-Results` header and are only as trustworthy as that server.
Natural extensions: URL reputation lookups, attachment hashing against
VirusTotal, and an LLM-written analyst summary grounded in the findings.
