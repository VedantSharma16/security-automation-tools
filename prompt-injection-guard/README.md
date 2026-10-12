# pigard — Prompt-Injection Guard & Red-Team Harness

Defensive tooling for LLM / RAG applications (OWASP LLM Top 10): scan untrusted
text for prompt injection, detect system-prompt leaks with canary tokens, and
measure how well a target holds up against an attack corpus. Stdlib only.

## Components

| Module | Purpose |
|---|---|
| `normalize.py` | Defeats evasion: NFKC, zero-width stripping, homoglyph folding, base64 layer decoding |
| `rules.py` | 9 rules (override, role hijack, jailbreak, prompt extraction, fake delimiters, exfil channels, covert tool use, indirect injection, secrecy) tagged with OWASP IDs |
| `scanner.py` | Scores risk 0–10 → `allow` / `warn` / `block`; retrieved documents (indirect injection) score higher; multi-category corroboration raises risk |
| `canary.py` | Plants a random marker in the system prompt; flags outputs containing it, even spaced or split |
| `harness.py` | 10-attack corpus + benign set run against any `callable(system_prompt, user_input) -> str`; reports leak rate, detection rate, false positives |

## Usage

```bash
pip install -e .[dev]
pigard scan suspicious.txt --source retrieved   # exit 0 allow / 1 warn / 2 block
echo "ignore all previous instructions" | pigard scan - --json
pigard redteam --target vulnerable              # leak_rate=60%, exit 1
pigard redteam --target guarded                 # leak_rate=0%, 0 false positives
pytest
```

To test a real model, pass your own client wrapper to `harness.run(target)`.

## Limitations

Regex rules are a first layer, not a complete defence: novel phrasings and
non-English attacks will slip through. Combine with least-privilege tools,
output filtering, and human approval for sensitive actions. The mock targets
exist to demonstrate measurement, not to claim real-model robustness.
