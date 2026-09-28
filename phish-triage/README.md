# phishtriage

A command-line tool that parses raw `.eml` files, runs a set of rule-based
phishing detectors over the headers, links, and attachments, and produces an
analyst-ready triage report — optionally with an LLM-written narrative.

Phishing is still the most common initial-access vector in real incidents,
and first-pass triage of a reported email follows a fairly mechanical
playbook: check sender authentication, check for brand/display-name
spoofing, check where links actually go versus what they claim, check
attachments. This tool automates that playbook so an analyst (or an
automated mail pipeline) gets a scored, evidence-backed verdict in seconds,
with every finding traceable to a specific header, link, or attachment —
no black-box "AI says it's phishing."

Same pattern as this repo's other triage tools: **detectors stay
deterministic and auditable; the LLM only writes prose on top of evidence
the detectors already produced.** The model never sees the raw email and is
explicitly instructed not to introduce facts beyond the structured findings
it's given.

## What it detects

| Detector | Pattern | ATT&CK technique | Default severity |
|---|---|---|---|
| Auth failure | SPF, DKIM, or DMARC reported `fail`/`softfail` | T1656 Impersonation | HIGH |
| Auth results missing | No `Authentication-Results` header at all | — | LOW |
| Display-name spoof | From display name names a brand the sending domain doesn't belong to | T1656 Impersonation | CRITICAL |
| Reply-To mismatch | Reply-To domain differs from the From domain | T1656 Impersonation | MEDIUM |
| Return-Path near-miss | Return-Path domain is a 1–2 character edit of the From domain | — | LOW |
| Suspicious URL | IP-literal host, known shortener, punycode/IDN homograph, `user@host` obfuscation, excessive subdomains, or brand-lookalike domain | T1566.002 Spearphishing Link | MEDIUM–HIGH |
| Link text mismatch | An HTML link's visible text names one domain but `href` points elsewhere | T1566.002 Spearphishing Link | HIGH |
| Dangerous attachment | Executable/script extension, macro-enabled Office document, or a double extension (`invoice.pdf.exe`) | T1566.001 Spearphishing Attachment | CRITICAL |
| Urgency language | Body text matches credential-harvest/urgency phrasing | T1598 Phishing for Information | LOW |

The brand-lookalike check normalizes leetspeak substitutions (`paypa1` →
`paypal`) and checks both substring impersonation and edit distance, against
a small, easily-extended list of commonly spoofed brand domains
(`phishtriage/urls.py::COMMON_BRAND_DOMAINS`).

Findings are combined into a 0–100 risk score and an overall verdict
(`benign` / `suspicious` / `malicious`), rendered as JSON or Markdown.

## Install

```bash
cd phish-triage
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
phishtriage scan path/to/message.eml
phishtriage scan path/to/message.eml --format json --out report.json
phishtriage scan path/to/message.eml --llm                     # use Claude for the narrative
phishtriage scan path/to/message.eml --fail-on-risk 50          # exit 1 if risk >= 50, for pipelines
```

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic, offline template summarizer — the tool is always usable
without any API key or network access, and never sends email content
anywhere unless `--llm` is explicitly passed.

Try it against the included fixtures:

```bash
phishtriage scan tests/fixtures/phishing_paypal.eml       # spoofed sender, failed auth, malicious link + attachment
phishtriage scan tests/fixtures/suspicious_shortlink.eml  # single weak signal -> "suspicious", not "malicious"
phishtriage scan tests/fixtures/benign_newsletter.eml     # clean, well-authenticated mail -> zero findings
```

## Architecture

```
phishtriage/
  parser.py            .eml bytes -> structured Message (headers, body text/html, attachments)
  headers.py            SPF/DKIM/DMARC parsing, sender/reply-to/display-name checks
  urls.py                URL extraction, defanging, and the static link-risk heuristics
  attachments.py         filename/extension-based attachment risk classification
  detectors.py           Message -> Finding list (7 independent, ATT&CK-mapped rules)
  scoring.py             Finding list -> severity breakdown, 0-100 risk score, verdict
  report.py              Message + findings -> structured report dict, JSON/Markdown rendering
  llm_summarizer.py      report dict -> narrative text (TemplateSummarizer or AnthropicSummarizer)
  cli.py                 argparse entry point wiring the above together
```

Each stage takes the previous stage's output and nothing else, so every
piece is independently unit-testable — see `tests/`, which covers the
parser, header/URL/attachment heuristics, each detector, scoring, report
rendering, the summarizer fallback logic, and the CLI end-to-end via
subprocess. All fixtures in `tests/fixtures/` are synthetic emails generated
for testing; nothing is fetched over the network at any point.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## Why this design

No content-fetching or reputation lookups happen anywhere in this tool —
every check is a static, explainable rule over the message's own headers,
link text, and filenames, the same class of signal a mail gateway or a
first-pass SOC analyst uses before ever visiting a link. That keeps the tool
safe to run against a suspected-malicious sample (nothing is clicked,
downloaded, or resolved) and keeps every finding traceable to a concrete
piece of evidence rather than an opaque model judgment.
