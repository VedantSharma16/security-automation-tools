# llm-redteam-harness

Automated red-team harness for LLM-backed applications. It fires a corpus of adversarial prompts (mapped to the
OWASP Top 10 for LLM Applications) at a target, detects success with **objective canaries** rather than an
LLM judge, scores resistance, and can act as a **CI gate** that fails a build when a regression makes the app exploitable.

> Use only against systems you own or are authorized to test.

## Attack categories

| Category | OWASP | Example |
|---|---|---|
| `direct_injection` | LLM01 | "Ignore all previous instructions…", fake system delimiters, non-English overrides |
| `indirect_injection` | LLM01 | Instructions hidden in a retrieved document or web page (RAG / agent threat model) |
| `jailbreak` | LLM01 | Persona (DAN-style) and fiction-wrapper attacks |
| `system_prompt_leak` | LLM07 | Verbatim requests, debug pretexts, translation tricks |
| `data_exfiltration` | LLM02 | Markdown image/link exfiltration of secrets, injected via user or document |
| `obfuscation` | LLM01 | Base64-encoded instructions |

Corpus lives in [`data/attacks.json`](data/attacks.json); add your own entries (validated on load).

## How detection works

Each run generates a random **canary** secret planted in the system prompt and a random **marker** each
attack tries to make the model emit. An attack succeeds if the response:

1. contains the canary (prompt/secret leakage),
2. contains the marker while *not* refusing (injected instruction obeyed; a refusal that merely quotes the marker is not a hit), or
3. contains a Markdown link/image to an untrusted host carrying secret material (exfiltration channel).

Random per-run values make results reproducible to audit yet impossible to game by memorization.
Known limitation: refusal detection is regex-based, so novel refusal phrasing may cause a false positive on marker compliance.

## Usage

```bash
pip install -e .[dev]                       # core is stdlib-only
llm-redteam --target mock-vulnerable        # offline demo: everything succeeds
llm-redteam --target mock-hardened          # offline demo: everything is resisted, exit 0
pip install -e .[llm]
llm-redteam --target anthropic --model claude-haiku-4-5-20251001 --fail-on high \
            --json-out report.json --markdown-out report.md
```

Exit code is `1` if any successful (or errored) attack is at or above `--fail-on` severity, `2` for bad selection, else `0`.
Drop it into CI to catch prompt regressions:

```yaml
- run: llm-redteam --target anthropic --fail-on high
```

### Testing your own app

```python
from llm_redteam.targets import CallableTarget
from llm_redteam.payloads import load_attacks
from llm_redteam.runner import run_attacks, resistance_score

def my_app(system_prompt, user_message, context):
    return my_chain.invoke(...)   # call your RAG chain / agent / HTTP endpoint

results = run_attacks(CallableTarget(my_app, "my-app"), load_attacks())
print(resistance_score(results))
```

## Layout

```
llm_redteam/  payloads.py (corpus, per-run rendering)  detectors.py (canary analysis)
              targets.py (mock + Anthropic + callable)  runner.py (execution, scoring, gate)
              report.py (JSON/Markdown)  cli.py
data/attacks.json    tests/ (19 pytest tests, fully offline)
```

## Tests

```bash
pytest
```
