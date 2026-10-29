# promptprobe: prompt-injection red-team harness

A small, dependency-free harness that fires a corpus of prompt-injection and
jailbreak probes at an LLM application, detects whether each one *actually
worked* from the output, and reports an OWASP-LLM-mapped risk score. It also
ships a transparent heuristic **input guard** so the same tool measures both
the attack (red team) and the defence (blue team).

## What it does

- **16 attacks** across 7 categories: instruction override, jailbreak/persona,
  system-prompt leakage, secret exfiltration, indirect injection (poisoned
  documents), obfuscation (base64, multilingual, payload splitting) and
  excessive agency (tool coercion). Each maps to an OWASP Top 10 for LLM
  Applications ID (LLM01/02/06/07).
- **Outcome-based detectors**, not keyword guessing on the prompt: canary
  credential leaked, system-prompt n-gram overlap, markdown-image exfiltration
  beacon, and an injected marker string proving the model obeyed.
- **Targets**: an intentionally vulnerable mock app, a hardened mock, any target
  wrapped in the guard, or a real Claude model (`anthropic[:model]`, needs the
  `llm` extra and `ANTHROPIC_API_KEY`). Add your own with a `respond()` method.
- **CI gate**: `--fail-above N` exits 1 when the severity-weighted risk score
  exceeds N, so prompt regressions can fail a pipeline.
- **Input guard**: weighted regex rules (with base64 decoding) that list which
  rules fired for every verdict.

## Usage

```bash
pip install -e ".[dev]"            # or just run from this directory
python -m promptprobe run --target vulnerable            # Markdown report
python -m promptprobe run --target vulnerable+guard --format json
python -m promptprobe run --target anthropic:claude-haiku-5-5 --fail-above 20
python -m promptprobe check "Ignore all previous instructions"   # guard only
pytest
```

Sample result against the bundled vulnerable mock: 14/16 attacks succeed
(risk 89/100); wrapped in the guard, 0/16 succeed; the hardened mock scores 0.

## Honest limitations

- The guard's rules were written against this corpus, so its 0% is optimistic.
  The tests include benign prompts (no false positives) **and held-out
  evasions it misses** (paraphrase, non-English phrasing) to keep that visible.
  Pattern matching is defence in depth, not a fix for prompt injection.
- Mock targets are deterministic stand-ins for testing the harness itself; use
  a real target for meaningful numbers. Success detection is heuristic.
- Only test systems you are authorised to assess.

## Layout

```
promptprobe/  attacks.py  detectors.py  guard.py  harness.py  targets.py  report.py  cli.py
tests/        harness, detectors, guard (benign + evasion), CLI gate
```
