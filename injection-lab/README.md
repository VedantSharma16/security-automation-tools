# injection-lab

A prompt-injection **red-team harness** and **input guard** for LLM applications.
It answers two questions: *how easily can my LLM app be talked out of its
instructions?* and *how much does a defence actually help (and what does it
break)?*

Maps to OWASP Top 10 for LLM Applications: LLM01 (Prompt Injection),
LLM02 (Sensitive Information Disclosure), LLM07 (System Prompt Leakage).

## How it works

1. **Payload corpus** (`injectionlab/payloads.json`): 13 attacks across
   instruction override, prompt leaking, roleplay jailbreaks, delimiter
   injection, encoding evasion (base64 / leetspeak), indirect injection
   (hidden instructions in documents) and markdown-image exfiltration, plus
   benign prompts to measure false positives.
2. **Canary judging**: the system prompt contains a unique canary token. An
   attack "succeeds" only if the canary or system prompt leaks into the
   response, so scoring is objective, not vibes.
3. **Targets**: any `(system_prompt, user_input) -> str` callable.
   Built-ins: a deliberately `vulnerable` mock, a `guarded` mock (same model
   behind the guard), and an `anthropic` target for real models.
4. **Guard** (`guard.py`): transparent weighted-regex scoring. Evidence is
   combined as `1 - Π(1 - wᵢ)`; input is also leetspeak-normalised and
   base64-decoded before scanning, so simple encoding evasions are caught.
5. **Reports**: Markdown or JSON, with per-category failures, attack success
   rate and false-positive rate.

## Usage

```bash
pip install -e ".[dev]"            # stdlib-only core
injection-lab run --target vulnerable
injection-lab run --target guarded --format json
injection-lab run --target anthropic --fail-above 0.2   # CI gate: exit 1 if ASR > 20%
injection-lab scan "Ignore all previous instructions"   # exit 1 if blocked
pytest
```

Sample result:

| Target | Attack success rate | False positives |
|---|---|---|
| vulnerable | 100% | 0% |
| guarded | 0% | 0% |

## Limitations (read this)

The guard is a heuristic *layer*, not a solution. The bundled corpus was
used while developing the rules, so the 0% figure is a regression baseline,
not a claim of robustness; novel paraphrases, other languages, or multi-turn
attacks will evade regexes. Use `--payloads` with your own corpus and treat
the guard as one control alongside privilege separation, output filtering and
least-privilege tool access. The mock targets are simulations; the
`anthropic` target is the real signal. Only test systems you are authorised
to test.

## Layout

```
injectionlab/  guard.py  harness.py  targets.py  cli.py  payloads.json
tests/         guard, harness and CLI tests (offline, no API calls)
```
