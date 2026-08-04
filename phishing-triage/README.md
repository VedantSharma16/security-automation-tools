# phishing-triage

A command-line tool that parses a raw `.eml` email and produces a scored,
evidence-grounded phishing triage report — the same shape of judgment call a
Tier-1 SOC analyst makes dozens of times a shift, made explicit, deterministic,
and auditable.

Phishing is the single most common initial-access vector IR teams deal with,
and it's the one category the other tools in this repo don't touch (they
cover log-based intrusion detection, IOC/alert triage, and host process
hunting). This project fills that gap.

Like the other projects here, it's **rule-based analysis with an optional LLM
narrative layer, never the other way around.** Every analyzer produces
structured, inspectable facts first; an LLM (or a deterministic offline
template, used by default) only turns those facts into prose. The model never
sees the raw email and cannot introduce a finding that isn't already in the
JSON it's handed — which keeps the tool trustworthy for something as
consequential as "is this a phishing attempt."

## What it checks

| Analyzer | Signal |
|---|---|
| `auth_analysis.py` | SPF / DKIM / DMARC verdicts, read from the receiving server's own `Authentication-Results` header (no DNS re-checks against records that may have since changed) |
| `url_analysis.py` | Per-link: raw-IP hosts, `user@host` userinfo spoofing, punycode homographs, URL shorteners, abused TLDs, credential-harvest path keywords, brand impersonation, and displayed-text vs. actual-href mismatches |
| `content_analysis.py` | Urgency/pressure language, requests for sensitive info (passwords, SSNs, gift cards, wire transfers), generic non-personalized greetings, sender display-name brand impersonation, and dangerous/disguised (double-extension) attachments |

Findings are combined into a 0–100 score and a `benign` / `suspicious` /
`likely_phishing` verdict.

## Install

```bash
cd phishing-triage
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
phishing-triage suspicious_email.eml
phishing-triage suspicious_email.eml --json --out report.json
phishing-triage suspicious_email.eml --llm          # Claude-written narrative
cat suspicious_email.eml | phishing-triage           # reads from stdin too
```

Exit codes: `0` = benign, `1` = suspicious or likely phishing (findings
reported), `2` = fatal error (missing/unparseable file) — so it can gate a
mail-pipeline step or CI job the same way the other tools in this repo do.

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to a
deterministic, offline template summarizer — always usable with no API key or
network access.

Try it against the included samples:

```bash
phishing-triage examples/phishing_sample.eml     # typosquat domain, spoofed link, malicious attachment
phishing-triage examples/legitimate_sample.eml    # clean GitHub notification, zero findings
```

## Example output

```
$ phishing-triage examples/phishing_sample.eml --no-color
Phishing Triage Report
From    : PayPal Security Team <security@paypa1-support.tk>
Subject : Urgent Action Required: Your Account Has Been Suspended
Verdict : LIKELY PHISHING (score 100/100)
Auth    : spf=fail dkim=fail dmarc=fail (header present: True)
Links   : 2   Attachments: 1

Findings:
  - SPF check failed for the sending server
  - DKIM signature failed verification
  - DMARC alignment failed
  - link uses userinfo spoofing -- browser navigates to 'secure-login.paypa1-verify.tk',
    but the URL displays 'paypal.com' before the '@' to look legitimate
  - link references brand 'paypal' but host 'secure-login.paypa1-verify.tk' is not a
    known paypal domain
  - display name 'PayPal Security Team' claims to be 'paypal', but the sending address
    domain 'paypa1-support.tk' is not a known paypal domain
  - attachment 'invoice.pdf.exe' uses a disguised double extension to hide its true,
    executable type
  ...
```

## Architecture

```
phishing_triage/
  parser.py            .eml bytes -> ParsedEmail (headers, text/html body, links, attachments)
  brands.py             shared brand-keyword -> legitimate-domain allowlist
  auth_analysis.py      Authentication-Results header(s) -> AuthResult (spf/dkim/dmarc)
  url_analysis.py       ParsedEmail.links -> per-link UrlFinding
  content_analysis.py   subject/body/sender/attachments -> ContentFindings, SenderFinding, AttachmentFinding
  scoring.py             all findings -> TriageResult (0-100 score + verdict)
  llm_summarizer.py     report dict -> narrative text (TemplateSummarizer or AnthropicSummarizer)
  report.py              assembles everything into one report dict; JSON + console rendering
  cli.py                 argparse entry point wiring the above together
```

Each stage consumes only the previous stage's output, so every piece is
independently unit-tested — see `tests/`, which covers the parser, each
analyzer, scoring (including the per-category weight caps), the summarizer
fallback logic, report rendering, and the CLI end-to-end via subprocess.
Parsing uses only the standard library (`email`, `html.parser`,
`urllib.parse`) — no BeautifulSoup or third-party MIME library needed for the
shallow, targeted extraction this tool does.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

62 tests, fully offline and deterministic (no network access, no live
`ANTHROPIC_API_KEY` required — the LLM path is exercised only via its
fallback behavior).

## Limitations & honest caveats

- **Heuristic, not a detection engine.** The brand/TLD/shortener lists are
  small and illustrative. A determined attacker using a fresh `.com` domain
  with no brand keyword in sight will score lower than the phishing sample
  here. Treat this as a triage aid that surfaces likely candidates for human
  review, not a spam filter replacement.
- **SPF/DKIM/DMARC are read, not re-verified.** The tool trusts the
  `Authentication-Results` header stamped by whatever mail server received
  the message. A forged or stripped header (possible if the .eml wasn't
  captured directly from the mailbox) would produce a false negative on
  `header_present`.
- **No sandboxing.** Attachments are inspected by filename/extension only;
  nothing is executed, opened, or scanned for actual malware content.

## Why this design

Real anti-phishing tooling (Proofpoint, Mimecast, M365 Defender) runs exactly
this shape of pipeline: cheap, deterministic, explainable checks first,
because a security control that flags a message needs to be able to say
*why* — both for analyst trust and for compliance/audit trails. This project
keeps that property end to end and adds an LLM purely for what it's actually
good at: turning a JSON of findings into a readable analyst narrative,
instead of asking a model to read raw email content and decide for itself
whether it's malicious.
