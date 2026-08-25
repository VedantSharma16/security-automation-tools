# Phishing Triage Agent

A tool-calling **agentic** pipeline that investigates a raw `.eml` message
and produces a phishing/suspicious/benign verdict, backed by a transparent
trace of exactly which investigation tools were run and what they found.

This is deliberately the "agent" counterpart to this repo's other two
LLM-integrated tools: [`ioc-triage-assistant/`](../ioc-triage-assistant/) is
a RAG pipeline (retrieval over a fixed corpus) and
[`log-triage-assistant/`](../log-triage-assistant/) uses an LLM purely to
narrate results a rule engine already computed. Here, the model itself
drives the investigation — deciding *which* tools to call and *in what
order* based on what it has already observed, the way a SOC analyst
actually works a ticket, rather than following a fixed pipeline.

## Why this exists

Phishing triage is one of the highest-volume, most repetitive tasks in a
SOC, and one of the clearest fits for LLM tool-use: the analyst doesn't run
every possible check on every email in a fixed order — they read the
headers, and *decide* what to check next based on what they see. This
project builds that adaptive investigation loop for real, using Anthropic's
native tool-use (function-calling) API, and pairs it with a fully offline,
deterministic fallback so the tool — and its test suite — never require an
API key or network access.

## How the agent decides what to do

In **live** mode (`ANTHROPIC_API_KEY` set), `PhishingAgent` hands the model
six investigation tools plus a `submit_verdict` tool:

| Tool | What it checks |
|---|---|
| `parse_headers` | Display-name vs. sending-domain mismatches, brand impersonation, Return-Path/From mismatch |
| `check_authentication` | SPF/DKIM/DMARC results from the `Authentication-Results` header |
| `extract_urls` | Every URL found in the body |
| `check_url_reputation` | Known-malicious domains, typosquatting/combosquatting of trusted brands, punycode homographs, raw-IP URLs |
| `check_attachments` | Risky and double (`invoice.pdf.exe`) file extensions |
| `analyze_language` | Urgency / social-engineering phrase detection |

The model calls tools across multiple turns via Anthropic's tool-use API,
sees each tool's JSON observation, and decides what to check next — it can
skip tools that won't add new evidence, and stops by calling
`submit_verdict` with its verdict, confidence, reasoning, and cited
evidence. If it runs past `--max-steps` without submitting a verdict, the
agent falls back to the same deterministic scorer offline mode uses, rather
than leaving the analyst with nothing.

In **offline** mode (no key, or `anthropic` isn't installed), the agent runs
all six tools in a fixed order and scores the combined evidence with a
deterministic rule (known-malicious hit, typosquat, failed auth, risky
attachment, and urgency language all contribute points; the total maps to
benign/suspicious/phishing). Both modes return the exact same
`AgentResult` shape — verdict, confidence, reasoning, evidence, and a full
tool-call trace — so the report and CLI don't need to know which mode ran.

## Quickstart

```bash
cd phishing-triage-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live agentic mode
pytest -q

phishing-agent --file examples/phishing_sample.eml
phishing-agent --file examples/benign_sample.eml --json
cat examples/phishing_sample.eml | phishing-agent
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m phishing_agent.cli --file examples/phishing_sample.eml
```

### Enabling the live agentic mode

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
phishing-agent --file examples/phishing_sample.eml
```

Without a key, the CLI reports `Agent mode: offline (deterministic sweep)`
and still produces a complete, evidence-backed verdict.

Exit codes: `0` if the verdict is `benign`, `1` otherwise — so it can gate a
mail-pipeline or SOAR step.

## Example output

Running against `examples/phishing_sample.eml` (a synthetic email spoofing
PayPal — failed SPF/DKIM/DMARC, a typosquatted C2-style domain, urgency
language, and a double-extension attachment):

```
🔴 Verdict: PHISHING  (confidence 95%)
Agent mode: offline (deterministic sweep)
Subject: 'Urgent Action Required: Unusual Activity Detected On Your Account'  From: PayPal Security <alerts@paypa1-secure.com>

Key evidence:
  - Display name impersonates 'PayPal' but the sending domain is 'paypa1-secure.com'.
  - Authentication failed: spf=fail, dkim=fail, dmarc=fail.
  - URL domain 'paypa1-secure.com' matches a known-malicious feed entry.
  - URL domain 'paypa1-secure.com' is a likely typosquat of 'paypal.com' (PayPal, edit distance 1).
  - Attachment 'account_statement.pdf.exe' uses a suspicious double extension.
  - Urgency/social-engineering language detected: verify your account, ...

Investigation trace (6 tool call(s)):
  1. parse_headers
  2. check_authentication
  3. extract_urls
  4. check_url_reputation
  5. check_attachments
  6. analyze_language
```

`examples/benign_sample.eml` (a normal internal email, clean auth, no
links or attachments) is correctly scored `BENIGN`.

## Project layout

```
phishing-triage-agent/
├── phishing_agent/
│   ├── email_parser.py   # stdlib email parsing -> ParsedEmail
│   ├── heuristics.py      # typosquat/homograph/urgency-language/attachment logic
│   ├── tools.py             # the 6 investigation tools + Anthropic tool schemas
│   ├── agent.py             # the ReAct-style tool-use loop + offline fallback
│   ├── report.py            # human-readable rendering
│   └── cli.py                 # argparse CLI
├── data/
│   ├── trusted_brands.json          # commonly-impersonated brand domains
│   └── known_malicious_domains.json # synthetic demo threat-intel feed
├── examples/
│   ├── phishing_sample.eml
│   └── benign_sample.eml
└── tests/                    # pytest, fully offline (live mode tested via a mocked client)
```

## Design notes / limitations

- **Threat-intel and brand lists are synthetic/curated**, same as
  `ioc-triage-assistant`'s. `tools.DataFeeds.load_default()` is the seam to
  swap in a real feed or a brand-protection list.
- **Typosquat detection compares hyphen/dot-separated tokens of the
  domain**, not just the whole string, against each trusted brand's SLD —
  this catches real-world patterns like `paypal-secure-verify.com`
  (brand name + extra words) in addition to classic single-character
  substitutions (`paypa1.com`), at the cost of occasional false positives
  on short, coincidentally-similar tokens.
- **The offline scorer is a heuristic, not a verdict** — it's meant to keep
  the tool fully useful without an API key, not to replace the live mode's
  adaptive reasoning.
- **Live-mode tests never call the real API.** `tests/test_agent.py` injects
  a scripted fake Anthropic client to exercise the actual tool-dispatch and
  fallback logic deterministically and offline.

## Possible extensions

- Add a `check_display_language`/homoglyph-in-subject tool (Unicode
  confusables beyond punycode domains).
- Swap the synthetic feeds for a real threat-intel API (VirusTotal, OTX) or
  an internal brand-protection list.
- Add a `--mbox`/maildir batch mode for triaging a phishing mailbox instead
  of one message at a time.

## Testing

```bash
pytest -q
```

35 tests cover email parsing, each heuristic (Levenshtein, typosquat
detection, homograph/punycode, urgency language, risky attachments), each
investigation tool against both example emails, the offline agent sweep,
the live tool-use loop and its max-steps fallback (via a mocked Anthropic
client), and the CLI itself. No network access or API key is required.
