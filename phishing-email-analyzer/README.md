# phishtriage

A command-line tool that parses a raw `.eml` file, runs rule-based phishing
heuristics over it, and produces a triage report with a risk score and
verdict — optionally with an LLM-written analyst narrative.

Like the other tools in this repo, it follows a **deterministic-first**
design: every heuristic is auditable rule-based logic; the LLM only writes
prose on top of findings that already exist. The model never sees the raw
email and is explicitly instructed not to introduce facts beyond the
structured findings it's given, which keeps the narrative grounded and
reviewable — exactly what you'd want before acting on it in a SOC.

## What it detects

| Heuristic | Pattern | Default severity |
|---|---|---|
| Auth failure | SPF, DKIM, or DMARC fails per the receiving gateway's `Authentication-Results` header | HIGH / CRITICAL if DMARC fails |
| Auth missing | No `Authentication-Results` header present at all | LOW |
| Reply-To mismatch | `Reply-To` domain differs from the `From` domain | MEDIUM |
| Brand impersonation | Display name references a known brand (PayPal, Microsoft, banks, …) but the sending domain isn't one of that brand's real domains | HIGH |
| Lookalike domain | Sending domain is within edit-distance 2 of a known brand's real domain (typosquat, e.g. `paypa1.com`) | HIGH |
| Raw-IP link | A link's host is a bare IP address instead of a domain | HIGH |
| URL shortener | A link uses a known shortening service (bit.ly, tinyurl, …) | MEDIUM |
| Link cloaking | Anchor text shows one domain while the `href` points to another | CRITICAL |
| Urgency language | Subject/body uses pressure phrasing ("verify your account", "act now", …) | LOW |
| Dangerous attachment | Attachment extension can execute code/macros (`.exe`, `.js`, `.docm`, …), including double-extension masquerading like `invoice.pdf.exe` | CRITICAL |

Findings feed a 0–100 risk score and a `benign` / `suspicious` /
`likely_phishing` verdict, rendered as JSON or Markdown.

Known-brand domains used for impersonation/typosquat checks live in
[`data/known_brands.json`](data/known_brands.json) and are trivially
extensible.

## Install

```bash
cd phishing-email-analyzer
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
phishtriage scan path/to/email.eml
phishtriage scan path/to/email.eml --format json --out report.json
phishtriage scan path/to/email.eml --llm             # use Claude for the narrative
```

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic, offline template summarizer — the tool is always usable
without any API key or network access.

Try it against the included fixtures:

```bash
phishtriage scan tests/fixtures/phishing_paypal.eml      # PayPal-impersonation phishing sample
phishtriage scan tests/fixtures/clean_newsletter.eml     # benign newsletter, zero findings
```

## Architecture

```
phishtriage/
  parser.py          .eml bytes -> ParsedEmail (headers, body, links, attachments)
  auth.py            Authentication-Results header -> SPF/DKIM/DMARC verdicts
  heuristics.py       ParsedEmail -> Finding list (6 independent, composable rules)
  scoring.py          Finding list -> severity breakdown + 0-100 risk score + verdict
  report.py            email + findings -> structured report dict, JSON/Markdown rendering
  llm_summarizer.py   report dict -> narrative text (TemplateSummarizer or AnthropicSummarizer)
  cli.py               argparse entry point wiring the above together
```

Each stage takes the previous stage's output and nothing else, so every
piece is independently unit-testable — see `tests/`, which covers the
parser, auth-header parsing, each heuristic, scoring, report rendering,
the summarizer fallback logic, and the CLI end-to-end via subprocess.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## Why this design

Phishing triage is a high-volume, high-stakes SOC workflow: an analyst (or
an automated pipeline) needs a fast, explainable verdict on a reported
email, not a model's unstructured opinion about whether "it looks phishy."
Keeping every signal — auth failures, domain typosquats, link cloaking,
dangerous attachments — as a deterministic, evidence-carrying rule means
the verdict is reproducible and the reasoning is inspectable line by line.
The LLM is layered on only to do what it's actually good at: turning that
structured evidence into a readable narrative for a human to act on,
without ever being trusted to invent facts about the email itself.
