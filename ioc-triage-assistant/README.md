# IOC Triage Assistant

A small pipeline that turns a raw SOC alert or log excerpt into a structured
triage report: it extracts indicators of compromise (IOCs), checks them
against a local threat-intel feed, retrieves the most relevant MITRE ATT&CK
techniques with a from-scratch RAG implementation, and produces an
analyst-facing summary — using an LLM when available, and a deterministic
offline fallback when it isn't.

It's a deliberately small, fully offline-runnable demo of the same shape of
pipeline used in real alert-triage / SOAR tooling, built to show both
security-analysis fundamentals (IOC parsing, defanging, ATT&CK mapping) and
applied AI-engineering fundamentals (retrieval, prompt construction, graceful
LLM fallback).

## Why this exists

Most "IOC extractor" demos stop at regex. Most "RAG demo" projects hide the
retrieval math behind a vector-database SDK. This project keeps both pieces
visible and testable:

- **IOC extraction** handles analyst conventions like defanged indicators
  (`185[.]220[.]101[.]1`, `hxxps://`) and filters obvious false positives
  (filenames like `explorer.exe`, dotted usernames like `j.morales`) using a
  known-TLD allowlist — a real precision problem naive domain regexes hit
  immediately.
- **RAG retrieval** is a ~100-line pure-Python TF-IDF + cosine-similarity
  index over a curated MITRE ATT&CK technique subset — no numpy, no vector
  DB — so the retrieval logic itself is inspectable.
- **LLM integration** is optional. Without `ANTHROPIC_API_KEY` set, the tool
  still produces a complete, structured, useful report via a templated
  offline summary. This keeps the test suite (and the tool itself) fully
  functional without any API key or network access.

## Pipeline

```
raw alert text
      │
      ▼
 extractor.py   ── refang + regex → IPs, domains, URLs, emails, hashes, CVEs
      │
      ▼
 enrichment.py  ── check each IOC against data/known_malicious_indicators.json
      │               + flag RFC1918 / loopback / link-local IPs
      ▼
 knowledge_base.py ── TF-IDF retrieval of top-k relevant ATT&CK techniques
      │                  from data/mitre_attack_techniques.json
      ▼
 triage.py      ── heuristic severity scoring (low/medium/high/critical)
      │
      ▼
 llm_client.py  ── build a RAG-augmented prompt; call Claude if a key is
      │               present, else render a deterministic offline summary
      ▼
 TriageReport (human-readable or JSON)
```

## Quickstart

```bash
cd ioc-triage-assistant
pip install -e ".[dev]"        # add ".[dev,llm]" for live Claude summaries
pytest -q

ioc-triage --file examples/sample_alert.txt
ioc-triage --file examples/sample_alert.txt --json
cat examples/sample_alert.txt | ioc-triage
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m ioc_triage.cli --file examples/sample_alert.txt
```

### Enabling live LLM summaries

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
ioc-triage --file examples/sample_alert.txt
```

Without a key, the CLI prints `LLM-backed: no (offline heuristic fallback)`
and still produces a complete report — the offline summary is built directly
from the structured triage context (flagged indicators, matched ATT&CK
techniques, severity), not a placeholder string.

## Example output

Running against `examples/sample_alert.txt` (a synthetic alert: encoded
PowerShell, a scheduled-task persistence mechanism, and C2 beaconing to a
known-malicious IP/domain):

```
🟠 Severity: HIGH
LLM-backed: no (offline heuristic fallback)

Indicators found (6):
  - [domain] evil-c2-panel.com
  - [domain] update-service-cdn.net
  - [ipv4] 10.20.4.17
  - [ipv4] 185.220.101.1
  - [md5] 44d88612fea8a8f36de82e1278abb02f
  - [url] https://evil-c2-panel.com/checkin

Known-malicious hits (4):
  - evil-c2-panel.com (domain) — high confidence: Registered domain matching a known C2 panel naming pattern.
  - update-service-cdn.net (domain) — medium confidence: Lookalike domain impersonating legitimate update infrastructure.
  - 185.220.101.1 (ipv4) — high confidence: Known Tor exit node observed proxying C2 traffic in prior incidents.
  - 44d88612fea8a8f36de82e1278abb02f (md5) — high confidence: MD5 of the EICAR test file family used in this demo dataset.

Matched ATT&CK techniques:
  - T1204 User Execution (Execution) [relevance=0.32]
  - T1053 Scheduled Task/Job (Execution, Persistence, Privilege Escalation) [relevance=0.25]
  - T1003 OS Credential Dumping (Credential Access) [relevance=0.14]
```

## Project layout

```
ioc-triage-assistant/
├── ioc_triage/
│   ├── extractor.py      # IOC regex extraction + defanging
│   ├── enrichment.py      # local threat-intel lookup + private-IP checks
│   ├── knowledge_base.py  # pure-Python TF-IDF RAG index over ATT&CK
│   ├── llm_client.py      # Claude API call + offline summary fallback
│   ├── triage.py          # orchestration + severity heuristic
│   └── cli.py              # argparse CLI
├── data/
│   ├── known_malicious_indicators.json  # synthetic demo threat-intel feed
│   └── mitre_attack_techniques.json      # curated ATT&CK technique subset
├── examples/sample_alert.txt
└── tests/                  # pytest, fully offline
```

## Design notes / limitations

- **Threat-intel feed is synthetic.** `data/known_malicious_indicators.json`
  is a small illustrative dataset for the demo, not live intelligence.
  `enrichment.load_threat_intel()` is the seam to swap in a real feed (MISP,
  OTX, VirusTotal, an internal blocklist API).
- **ATT&CK subset is curated, not complete.** `data/mitre_attack_techniques.json`
  covers ~15 common techniques for demo purposes. For production use, sync
  against the official STIX bundle at
  [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).
- **Severity scoring is a heuristic, not a verdict.** It's deliberately
  conservative: a retrieved ATT&CK technique alone (without a corroborating
  threat-intel hit) only counts toward severity above a stricter relevance
  bar, since retrieval similarity is context for the analyst, not proof of
  malicious intent.
- **Domain extraction uses a known-TLD allowlist** to cut down on false
  positives from filenames and dotted usernames. This trades a small amount
  of recall (obscure TLDs) for much better precision on the alert text
  domain typically produces.

## Testing

```bash
pytest -q
```

34 tests cover extraction (including defanging and false-positive
filtering), enrichment, RAG retrieval quality, the offline LLM fallback,
end-to-end triage severity scoring, and the CLI itself (as a subprocess, on
both human-readable and JSON output). No network access or API key is
required to run the suite.
