# llm-guard

A prompt-injection scanner and red-team harness for LLM applications. It maps
detections to the **OWASP Top 10 for LLM Apps** and **MITRE ATLAS**, and
measures how well a guard actually stops attacks. Stdlib-only, runs offline.

## Why this exists

The other tools in this repo use AI to help defenders. `llm-guard` goes the
other way: it secures AI systems themselves, which is a growing part of
application security and red teaming.

## What it does

**Scanner** (`llm_guard/scanner.py`)
1. **Normalizes** input: strips zero-width and bidi characters, applies NFKC,
   folds Cyrillic/Greek homoglyphs and leetspeak.
2. **Decodes** base64 (nested), hex and rot13 payloads, then scans every view.
3. **Matches** rules for instruction override, persona hijack, fake chat
   delimiters, indirect injection (RAG/web/email poisoning), system-prompt
   extraction, markdown/URL exfiltration, and dangerous tool requests.
4. **Scores** 0-10: top severity, plus corroboration, plus a bonus when the
   attack was obfuscated. Verdicts are `allow`, `review` and `block`.
5. **Output mode** finds leaked secrets (AWS keys, tokens, private keys, JWTs,
   SSNs) with redacted evidence, and detects a **canary token** planted in the
   system prompt.

**Red-team harness** (`llm_guard/redteam.py`)
Runs 10 attacks and 1 benign control against any `target(system, user) -> str`.
Success is judged by objective signals (canary leaked or marker echoed). It
reports attack success rate and false positives, with and without the guard.

## Usage

```bash
pip install -e '.[dev]'
echo "Ignore all previous instructions" | llm-guard scan      # exit 2 = block
llm-guard scan reply.txt --mode output --json
llm-guard redteam        # unguarded vs guarded against a deliberately naive demo bot
```

```python
from llm_guard import Scanner
r = Scanner().scan(user_text)
if r.verdict == "block": ...
```

To test a real model, pass your own callable to `run_redteam(target, Scanner())`.

## Results on the bundled corpus

Unguarded demo bot: 90% of attacks succeed. With the guard: 0% succeed and
0 false positives on the benign control.

## Limitations

Pattern-based detection is a first line of defense. It is not a complete one: a
determined attacker can paraphrase around regexes. Pair it with privilege
separation, output filtering and human confirmation for risky tool calls. The
demo bot and the small corpus show the method, not a benchmark.

## Tests

`python -m pytest` runs 24 tests, none of which touch the network.
