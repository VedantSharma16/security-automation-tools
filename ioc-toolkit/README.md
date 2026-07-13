# IOC Toolkit

A small, well-tested CLI for the first ten minutes of incident response
triage: pull indicators of compromise out of a raw report or log excerpt,
map any offensive-tool names to MITRE ATT&CK, and get a severity-scored
summary with recommended next steps — optionally narrated by Claude.

Built to show two things side by side: practical blue-team/IR tooling, and
an LLM integration written the way production AI code should be (optional
dependency, swappable backend, deterministic fallback, fully testable
without network access or an API key).

## Why this exists

Analysts spend a lot of time doing the same three things with a new threat
report or phishing email: pull out the IPs/domains/hashes/URLs, recognize
which offensive tools are mentioned, and decide how urgent it is. This
toolkit automates that first pass so a human can spend their time on
judgement calls instead of regex.

## Features

- **IOC extraction** — IPv4, IPv6, domains, URLs, emails, MD5/SHA1/SHA256
  hashes, and CVE IDs, deduplicated and type-tagged.
- **Defanged-input aware** — automatically refangs `1[.]2[.]3[.]4` /
  `hxxp://` style defanged indicators before extraction, since that's how
  most threat intel actually gets shared.
- **Defang / refang** — convert indicators to and from the safe-to-paste
  form for tickets, email, and chat.
- **ATT&CK enrichment** — a curated keyword table maps offensive-tool
  mentions (Mimikatz, PsExec, Cobalt Strike, Kerberoasting tools, etc.) to
  MITRE ATT&CK tactics/techniques.
- **Triage summary** — a rule-based severity score and recommended actions
  by default; if `ANTHROPIC_API_KEY` is set, an LLM-generated narrative
  summary instead. Same interface either way — the CLI doesn't know or
  care which backend produced the result.

## Architecture

```
raw text (defanged or not)
        │
        ▼
   refang (defang.py)
        │
        ▼
  extract IOCs (extractor.py)  ──┐
        │                       │
        ▼                       ▼
  ATT&CK enrichment      HeuristicSummarizer
   (enrichment.py)         or ClaudeSummarizer
        │                  (summarizer.py, picked
        │                   at runtime by get_summarizer())
        └──────────┬────────────┘
                    ▼
              cli.py (text or --json)
```

Each module has a single responsibility and no dependency on the others'
internals — `extractor.py` and `enrichment.py` operate on plain text and
return plain dataclasses, so they're trivial to unit test and reuse outside
the CLI (e.g. in a notebook or another pipeline).

## Install

```bash
cd ioc-toolkit
pip install -e .          # core toolkit, no LLM dependency
pip install -e ".[llm]"   # + anthropic, for Claude-backed summaries
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
# Extract IOCs from a file
ioc-toolkit extract examples/sample_report.txt

# Same, as JSON (for piping into another tool)
ioc-toolkit extract examples/sample_report.txt --json

# Defang/refang for safe pasting into a ticket
echo "1.2.3.4" | ioc-toolkit defang
echo "1[.]2[.]3[.]4" | ioc-toolkit refang

# Full triage report: IOCs + ATT&CK context + severity + next steps
ioc-toolkit report examples/sample_report.txt
```

```bash
$ ioc-toolkit report examples/sample_report.txt
Severity: HIGH (score: 15)

Extracted 6 indicator(s) across 6 type(s). Matched 3 known offensive-tool
keyword(s): mimikatz (T1003), psexec (T1569.002), powershell (T1059.001).
References 1 CVE(s): CVE-2024-3094.

ATT&CK matches:
  - mimikatz: OS Credential Dumping (T1003) — Credential Access
  - psexec: System Services: Service Execution (T1569.002) — Execution
  - powershell: Command and Scripting Interpreter: PowerShell (T1059.001) — Execution

Indicators:
  url: 1
  email: 1
  ipv4: 1
  sha256: 1
  cve: 1
  domain: 1

Recommended actions:
  - Submit file hashes to your EDR/AV and threat-intel platform for prevalence and reputation.
  - Check network/proxy/DNS logs for connections to the extracted hosts and add confirmed-bad ones to blocklists.
  - Cross-reference matched ATT&CK techniques against detection coverage and hunt for related activity.
  - Check asset inventory for exposure to the referenced CVE(s) and confirm patch status.
```

To use the Claude-backed narrative summary instead of the heuristic one,
set `ANTHROPIC_API_KEY` in the environment and install the `llm` extra —
`get_summarizer()` picks it up automatically, no flag needed.

## Testing

```bash
pip install -e ".[dev]"
pytest -v
```

The LLM backend is tested with a fake Anthropic client injected via
`ClaudeSummarizer(client=...)`, so the suite never makes a network call or
requires an API key.

## Known limitations

- The domain regex is a heuristic (valid-looking hostname + TLD shape) and
  is not validated against a real public-suffix list, so it can produce
  false positives on unusual but legitimate-looking strings — always
  cross-check before acting on an extracted indicator.
- The ATT&CK keyword table is intentionally small and curated for common
  red-team/malware tooling; it's a triage aid, not a detection engineering
  rule set.

## Project layout

```
ioc-toolkit/
├── src/ioc_toolkit/
│   ├── extractor.py     # IOC regex extraction
│   ├── defang.py        # defang/refang helpers
│   ├── enrichment.py     # ATT&CK keyword mapping
│   ├── summarizer.py     # heuristic + Claude-backed triage summary
│   └── cli.py            # argparse CLI
├── tests/                 # pytest suite, one file per module
├── examples/
│   └── sample_report.txt
└── pyproject.toml
```
