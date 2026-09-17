# phish-forensics

An offline-first phishing/BEC email triage tool for IR analysts and SOC
teams: point it at a raw `.eml` file and it parses headers, evaluates
SPF/DKIM/DMARC, extracts and classifies IOCs, flags brand-impersonation
attempts, and produces a triage report — optionally with an LLM-written
analyst narrative.

It fills a gap the rest of this repo doesn't cover yet: `log-triage-assistant`
and `process_threat_hunter` are host/log-centric, `ioc-triage-assistant`
starts from an already-extracted alert, and `recon-agent` is external
reconnaissance. Phishing/BEC email review is one of the highest-volume,
highest-value SOC tasks in practice, and this tool follows the same design
principle as the rest of the repo: **detection stays deterministic and
auditable; the LLM only writes prose on top of evidence the rule engine
already produced.** It never gets a vote on whether something is malicious.

> This tool only ever reads message metadata/content — it never fetches a
> URL, opens an attachment, or executes anything. IOCs in reports are always
> defanged (`hxxp://`, `1[.]2[.]3[.]4`) so they're safe to paste into tickets
> or chat.

## What it detects

| Category | Examples |
|---|---|
| Header/routing spoofing | From vs Reply-To vs Return-Path domain mismatches (classic BEC pattern: visible sender spoofed, replies routed to the attacker) |
| Brand impersonation | Display name claims a known brand but the sending domain doesn't match it; sender or link domain is a typosquat/homoglyph of a brand's real domain (`paypa1-support.com`, `micr0soft.com`, `paypal-secure-login.com`) |
| Authentication | Missing, failed, or partial SPF/DKIM/DMARC verdicts from the `Authentication-Results` header |
| Malicious links | Raw IP-address links, URL shorteners, abused TLDs, and the disguised-link tell where visible link text names one domain but the `href` points to another |
| Attachments | Executable/script extensions (`.exe`, `.js`, `.hta`, ...) and disguised double extensions (`invoice.pdf.exe`) — filenames and SHA-256 hashes only, nothing is opened |
| Social engineering | Urgency/pressure language ("account will be suspended", "verify immediately") as a supporting signal |

Findings feed a 0–100 risk score (same severity model as `log-triage-assistant`)
and render as Markdown or JSON.

## Install

```bash
cd phish-forensics
pip install -e .          # core tool, stdlib only, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
phish-forensics --eml suspicious.eml
phish-forensics --eml suspicious.eml --json --json-out report.json
phish-forensics --eml suspicious.eml --no-narrative   # skip the LLM step entirely
```

The narrative step uses Claude if `ANTHROPIC_API_KEY` is set (and the
`anthropic` package is installed), and otherwise falls back to a
deterministic offline summary — the tool is always fully usable without any
API key or network access. Exit code is `1` if the highest finding severity
is HIGH or CRITICAL (useful for pipeline gating), `0` otherwise.

Try it against the included fixtures:

```bash
phish-forensics --eml fixtures/phishing_paypal_bec.eml   # spoofed PayPal BEC attempt, 10 findings
phish-forensics --eml fixtures/benign_newsletter.eml     # well-authenticated newsletter, zero findings
```

## Architecture

```
phish_forensics/
  parser.py        raw .eml -> ParsedEmail (headers, bodies, HTML links, attachment hashes)
  htmlutils.py       dependency-free HTML -> text + (anchor text, href) link extraction
  authresults.py     Authentication-Results header(s) -> SPF/DKIM/DMARC verdicts
  iocs.py             URL/IP extraction, defang/refang, shortener/TLD/IP-literal classification
  lookalike.py        brand-impersonation detection (substring, edit-distance, homoglyph)
  heuristics.py       ParsedEmail + auth verdict -> list[Finding] (the rule engine)
  scoring.py          Finding list -> severity breakdown + 0-100 risk score
  report.py            everything above -> structured report dict, JSON/Markdown rendering
  narrative.py         report dict -> narrative text (Claude, or a grounded offline fallback)
  cli.py               argparse entry point wiring the above together
```

Every stage takes the previous stage's output and nothing else, so each
piece is independently unit-testable — see `tests/`, which covers the
parser, auth-results parsing, IOC extraction, lookalike-domain detection,
every heuristic rule, report rendering, the narrative fallback, and the CLI
end-to-end against the fixtures in `fixtures/`.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## Limitations

- Typosquat detection uses a small local brand list (`data/brands.json`) and
  a naive "second label before the TLD" split rather than a public-suffix-list
  parser — it won't handle multi-part TLDs like `.co.uk` correctly, and it
  only knows the brands seeded in that file.
- There's no live reputation/sandboxing (VirusTotal, URL sandboxing, WHOIS
  age lookups) — everything is inferred from the message itself, by design,
  so the tool has zero external dependencies and works fully air-gapped.
- Authentication-Results parsing trusts the header as received; if the
  upstream mail gateway itself is compromised or misconfigured, the verdict
  it reports can't be independently re-verified from the email alone.
