# phish-triage

Offline phishing email (`.eml`) analyzer for SOC / incident-response triage. Parses a message, runs
rule-based detectors mapped to MITRE ATT&CK, scores risk, and emits a human-readable or JSON report
plus extracted IOCs. Standard library only; no network calls.

## What it detects

| Area | Checks |
|---|---|
| Sender | Reply-To / Return-Path misalignment, brand display-name spoofing, lookalike domains (digit/homoglyph swaps like `paypa1`, `rn`→`m`, `brand-secure`, punycode) |
| Authentication | SPF / DKIM / DMARC fail, softfail, error; missing `Authentication-Results` |
| URLs | Raw-IP hosts, shorteners, punycode, `user@host` tricks, high-abuse TLDs, lookalike hosts, anchor text that shows one domain but links to another |
| Attachments | Double extensions (`invoice.pdf.exe`), executables/scripts, macro Office files, HTML/SVG smuggling, archives; SHA-256 for each |
| Content | Urgency/pressure language, urgency + credential prompt + link |

Scoring sums severity weights (capped at 100). Any critical finding or score ≥ 70 → `malicious`;
≥ 35 `suspicious`; ≥ 10 `low-risk`; else `clean`.

## Usage

```bash
pip install -e .[dev]
phishtriage tests/fixtures/phish.eml          # text report
phishtriage tests/fixtures/phish.eml --json   # machine-readable, includes IOCs
```

Exit codes (useful for gating a mail pipeline): `0` clean/low-risk, `1` suspicious, `3` malicious, `2` unreadable input.

## Tests

```bash
python -m pytest -q
```

## Design notes / limits

- Heuristics, not a verdict engine: lookalike detection uses a small built-in brand list and a crude
  registrable-domain split (no public-suffix list), so expect some false positives/negatives.
- Auth results are taken from the receiving MTA's `Authentication-Results`; signatures are not re-verified.
- Archives are flagged but not unpacked; attachments are hashed, never executed.
