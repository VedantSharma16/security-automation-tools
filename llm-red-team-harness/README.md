# redteam: LLM prompt-injection regression harness

A small, dependency-free harness that fires a corpus of prompt-injection,
prompt-extraction, jailbreak, indirect-injection and obfuscation attacks at an
LLM application and scores the result. Think "unit tests for your system
prompt": run it in CI and fail the build when a prompt or model change
re-opens a hole.

Attacks are mapped to the **OWASP Top 10 for LLM Applications** (LLM01
prompt injection, LLM02 sensitive information disclosure, LLM05 improper output
handling, LLM07 system prompt leakage).

## Design

- **Deterministic judging.** The app under test gets a system prompt containing
  a *canary secret*. Success is decided by detectors (canary leak incl.
  obfuscated forms, injected-marker echo, attacker-URL exfiltration, verbatim
  system-prompt runs), not by a second LLM, so results are reproducible.
- **Benign control.** A legitimate question is included; if a detector fires on
  it, the run is flagged (`control_failures`), guarding against false positives.
- **Offline by default.** `mock-naive`, `mock-partial` and `mock-hardened`
  targets simulate apps with different defences, so the harness and detectors
  are fully testable with no API key or network.
- **Pluggable targets.** Wrap your own app with `CallableTarget(fn)`, or use
  `--target anthropic[:model]` (needs `pip install -e ".[llm]"` and
  `ANTHROPIC_API_KEY`).
- **Resilient.** A target that raises is recorded as an error, not a crash.

## Usage

```bash
pip install -e ".[dev]"
redteam list
redteam run --target mock-partial
redteam run --target anthropic --format json --out report.json
redteam run --target mock-naive --category jailbreak
redteam run --target anthropic --fail-on-asr 0.1   # CI gate: exit 1 above 10% ASR
python -m pytest
```

Sample (`mock-partial`): ASR 3/11 (27%), risk score 36/100. Direct override and
secret requests are blocked, but the indirect injection, markdown-image
exfiltration and leetspeak probes get through.

## Metrics

- **ASR**: attack success rate over non-control attacks.
- **Risk score**: severity-weighted (low 1, medium 2, high 4, critical 8) share of
  attacks that succeeded, 0-100.

## Extending

Add an `Attack` to `redteam/attacks.py` and, if needed, a detector in
`redteam/detectors.py`; the corpus-integrity test checks every detector name resolves.

## Scope and limitations

The corpus is small and single-turn; a passing run is evidence of regression
safety, not proof of robustness. Use only against systems you own or are
authorised to test.
