# SOC Alert Triage Assistant

A small, dependency-free RAG (retrieval-augmented generation) pipeline that
triages raw security alerts by grounding them in a local MITRE ATT&CK
knowledge base, scoring them against known offensive-tooling and obfuscation
indicators, and producing an explainable severity verdict with recommended
next steps.

It's designed to sit at the intersection of two skill sets: SOC/incident
response triage (the domain problem) and applied AI engineering (the
retrieval + pluggable-LLM architecture used to solve it).

## Why this exists

Analysts drowning in alert volume need two things fast: *what technique does
this look like*, and *how bad is it*. This project answers both without
requiring an LLM call, an API key, or any external service — while leaving a
clean seam to plug a real LLM in for natural-language summaries.

## Architecture

```
alert (JSON) ─┐
              ├─► TechniqueRetriever  ──► top-k ATT&CK techniques (TF-IDF + cosine similarity)
              ├─► score_indicators()  ──► offensive-tool / obfuscation hits
              └─► TriageEngine
                     risk_score = 0.5 * top_technique_similarity + 0.5 * indicator_score
                     severity   = low / medium / high / critical
                     actions    = playbook for the top matched ATT&CK tactic
                     rationale  = narrator.summarize(...)   ◄── pluggable
```

- **Retrieval (`soc_triage/vectorizer.py`, `retriever.py`)** — a TF-IDF
  vectorizer and cosine similarity implemented from scratch in ~60 lines of
  stdlib Python (no scikit-learn/numpy). Alerts are embedded as text and
  matched against a small curated knowledge base of MITRE ATT&CK techniques
  (`data/attack_techniques.json`), so triage decisions are grounded in named,
  auditable technique IDs rather than an opaque model output.
- **Scoring (`soc_triage/scoring.py`)** — deterministic heuristics: known
  offensive-tool references (Mimikatz, Cobalt Strike, PsExec, etc.) and
  common obfuscation patterns (encoded PowerShell, hidden windows, remote
  payload downloads) each contribute to a 0–1 risk score, independent of any
  LLM.
- **Narration (`soc_triage/llm_backend.py`)** — a `TriageNarrator` protocol
  with two implementations:
  - `RuleBasedNarrator` (default): builds a summary string from the
    retrieved technique and indicators. Zero dependencies, fully
    deterministic — this is what the test suite and CI run against.
  - `ClaudeNarrator` (optional, `--use-claude`): sends the same evidence to
    the Claude API for a natural-language analyst summary. Only imports
    `anthropic` when actually selected, so it's never a hard dependency.

This split matters for anything security-adjacent: the severity verdict a
SOC would actually act on is never dependent on an LLM being available,
correctly prompted, or non-hallucinatory — the LLM only adds color commentary
on top of a deterministic decision.

## Usage

```bash
cd soc-alert-triage
pip install -r requirements.txt   # only needed to run tests (pytest)

python -m soc_triage --alerts data/sample_alerts.json
```

Example output (truncated):

```
[CRITICAL] ALERT-002  risk=0.85  [CRITICAL] Alert ALERT-002 on host SRV-DC01 (user svc_backup) most closely
resembles OS Credential Dumping (T1003). Indicators: offensive tool reference: mimikatz.
[HIGH    ] ALERT-008  risk=0.62  [HIGH] Alert ALERT-008 on host SRV-WEB01 (user svc_web) most closely
resembles Application Layer Protocol (T1071). Indicators: offensive tool reference: beacon.dll.
[LOW     ] ALERT-001  risk=0.02  [LOW] Alert ALERT-001 on host WKSTN-014 (user alice) most closely
resembles no strong technique match. Indicators: no known offensive indicators.
```

Write a full JSON report (all matched techniques, indicators, and playbook
actions per alert):

```bash
python -m soc_triage --alerts data/sample_alerts.json --output report.json
```

Use the Claude API for the narrative summary instead of the offline
rule-based one (requires `pip install anthropic` and `ANTHROPIC_API_KEY` set;
falls back to the offline narrator automatically if either is missing):

```bash
python -m soc_triage --alerts data/sample_alerts.json --use-claude
```

## Extending it

- **Bigger knowledge base**: `data/attack_techniques.json` currently has 12
  hand-picked techniques; swap in the full MITRE ATT&CK STIX bundle and
  `load_techniques()` keeps working unchanged.
- **Real embeddings**: `TechniqueRetriever` only depends on a vectorizer
  exposing `.fit()`/`.transform()` and a `cosine_similarity()` function —
  swap in sentence-transformers or an API embedding model without touching
  the retrieval or triage logic.
- **New indicators**: add patterns/tools to `soc_triage/scoring.py`.
- **New playbooks**: add tactics to `TACTIC_PLAYBOOKS` in the same file.

## Tests

```bash
pytest
```

Covers the vectorizer/cosine-similarity math, retrieval ranking against
known-technique queries, indicator scoring, severity boundaries, and
end-to-end triage of both a benign alert and a credential-dumping alert.

## Disclaimer

Educational/portfolio project for blue-team alert triage. The offensive-tool
list and ATT&CK mappings are illustrative, not exhaustive — this is not a
production detection engine.
