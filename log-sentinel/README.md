# log-sentinel

A small SOC-style pipeline: parse SSH auth logs → run deterministic
detection rules → triage each alert with an LLM that's grounded in a local
MITRE ATT&CK knowledge base.

It's built to show both sides of the same skill set: writing detection
logic the way a blue team would, and wiring an LLM into that pipeline the
way an AI engineer would — with a real retrieval step, a provider-agnostic
client boundary, and a deterministic offline mode so the whole thing is
testable without network access or an API key.

## Why this design

- **Detectors are plain, unit-testable rules.** No ML, no LLM in the
  detection path — an IR team needs alerts that fire for auditable reasons.
- **Retrieval is a real (if small) RAG step**, not a hardcoded lookup table.
  `KnowledgeBase.retrieve()` scores a local set of MITRE ATT&CK technique
  summaries by token overlap against the alert and pulls in the top matches
  as prompt context — the same shape as a production RAG pipeline, just
  with a lightweight scorer instead of an embedding index.
- **The LLM is swappable and optional.** `AlertTriageEngine` depends on an
  `LLMClient` protocol, not a concrete SDK. Pass in an `AnthropicClient` for
  live triage, a test double for unit tests, or nothing at all — in which
  case the engine falls back to a deterministic, still-useful summary. The
  CLI never crashes just because `ANTHROPIC_API_KEY` isn't set.

## Architecture

```
auth.log --> parser.py --> LogEvent[] --> detectors.py --> Alert[]
                                                              |
                                                              v
                                      knowledge_base.py (retrieve ATT&CK context)
                                                              |
                                                              v
                                          triage.py (AlertTriageEngine)
                                             |                |
                                    AnthropicClient      HeuristicSummary
                                    (--llm flag,          (default,
                                     needs API key)         offline)
```

## Detectors

| Rule ID | Name | Trigger |
|---|---|---|
| `SSH-001` | Brute-force attempt | ≥5 failed logins from one IP within 5 minutes |
| `SSH-002` | Compromised-account login | Successful login from an IP with ≥3 recent failures against it |
| `SSH-003` | Off-hours login | Successful login outside 08:00–20:00 |
| `SSH-004` | Privileged account login | Direct login as `root`/`admin`/`administrator` |

## Usage

```bash
cd log-sentinel
pip install -e .[dev]           # add the `llm` extra too if you want live triage

# Offline mode (no API key needed) — deterministic heuristic triage
python -m log_sentinel.cli data/sample_auth.log

# LLM-assisted triage via the Anthropic API
export ANTHROPIC_API_KEY=sk-...
python -m log_sentinel.cli data/sample_auth.log --llm
```

Sample output against `data/sample_auth.log` (offline mode):

```
Parsed 11 events, 5 alert(s) triggered.

======================================================================
[HIGH] SSH-001 - SSH brute-force attempt
5 failed password attempts from 203.0.113.7 within 5 minutes.
----------------------------------------------------------------------
Triage:
[offline triage] SSH brute-force attempt — severity high. 5 event(s) from
203.0.113.7 targeting user(s) admin, test, root. Recommend reviewing source
IP reputation and confirming activity with the account owner.

======================================================================
[CRITICAL] SSH-002 - Successful login following brute-force pattern
User 'root' successfully authenticated from 203.0.113.7 after 6 failed
attempts from the same address — likely a compromised credential.
----------------------------------------------------------------------
...
```

With `--llm`, each `Triage:` block instead contains a model-generated
assessment (likely intent, false-positive likelihood, recommended action)
grounded in the ATT&CK techniques `knowledge_base.py` retrieved for that
specific alert.

## Project layout

```
log-sentinel/
├── log_sentinel/
│   ├── models.py          # LogEvent, Alert, Severity
│   ├── parser.py          # syslog/sshd line parsing
│   ├── detectors.py       # rule-based detection engine
│   ├── knowledge_base.py  # local ATT&CK retrieval ("RAG-lite")
│   ├── triage.py          # LLM client protocol + triage engine
│   └── cli.py             # `python -m log_sentinel.cli`
├── data/
│   ├── sample_auth.log    # demo log with brute-force, compromise,
│   │                        off-hours, and benign events
│   └── mitre_attack_kb.json
└── tests/
    ├── test_parser.py
    ├── test_detectors.py
    ├── test_knowledge_base.py
    └── test_triage.py     # LLM calls mocked via a stub client
```

## Testing

```bash
pip install -e .[dev]
pytest
```

All 18 tests run offline and deterministically — including the triage
tests, which use a stub `LLMClient` rather than calling any API.

## Extending

- **New detectors**: implement a class with `rule_id` and `run(events) ->
  list[Alert]`, add it to `DEFAULT_DETECTORS` in `detectors.py`.
- **New log sources**: add a parser module that emits `LogEvent`s; nothing
  downstream (detectors, triage, CLI) needs to change.
- **Larger ATT&CK coverage**: extend `data/mitre_attack_kb.json` — no code
  changes required.
