# phish-triage

Offline triage of suspicious emails (`.eml`) for incident responders. Nothing is fetched or
executed: it parses the message, runs deterministic detections, maps hits to MITRE ATT&CK,
and returns a scored verdict. Stdlib-only, 11 pytest tests.

## What it detects

| Area | Checks |
|---|---|
| Header auth | SPF / DKIM / DMARC fail or missing (`Authentication-Results`, `Received-SPF`) |
| Sender | Reply-To / Return-Path domain mismatch, email-in-display-name spoofing, brand impersonation |
| URLs | Raw-IP hosts, shorteners, punycode homographs, leetspeak/fuzzy brand lookalikes (`paypa1.com`), `user@host` tricks, anchor text vs. real href mismatch, abused TLDs, non-HTTPS |
| Attachments | Executables/scripts, double extensions (`invoice.pdf.exe` = critical), macro Office files, archives |
| Content | Urgency / pressure phrases |

Scoring: severity-weighted with diminishing returns for repeated rules, capped at 100 →
`CLEAN` / `LOW-RISK` / `SUSPICIOUS` / `MALICIOUS`.

## Usage

```bash
pip install -e .[dev]
phishtriage tests/fixtures/phish.eml            # human-readable
phishtriage tests/fixtures/phish.eml --json     # machine-readable
phishtriage mail.eml --fail-on SUSPICIOUS       # exit 2 for SOAR / CI pipelines
pytest
```

Extracted domains are printed defanged (`evil[.]com`) so they are safe to paste into tickets.

## Layout

```
phishtriage/  parser.py  analyzers.py  scoring.py  report.py  cli.py  models.py
tests/        fixtures/{phish,clean}.eml
```

## Limitations

Heuristic only; it trusts the receiving MTA's authentication headers rather than
re-verifying signatures, and does no live reputation lookups. Extend `analyzers.py` with a
new `check_*` function and add it to `ALL_CHECKS`.
