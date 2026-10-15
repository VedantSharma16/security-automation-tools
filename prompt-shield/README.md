# prompt-shield

Heuristic **prompt-injection / jailbreak detection** and **output guarding** for LLM apps and RAG pipelines. Stdlib-only, offline, fast enough to run inline on every request.

Maps to OWASP Top 10 for LLM Applications: LLM01 (prompt injection), LLM02 (sensitive info disclosure), LLM06 (excessive agency), LLM07 (system prompt leakage).

## Why
LLM apps treat text as both data and instructions. Anything a model reads — user input, retrieved documents, tool output — can carry an attack. prompt-shield is a defensive layer that scores that text before the model sees it, and checks what comes back.

## Features
- **13 rule categories**: instruction override, role hijack, jailbreak personas, system-prompt extraction, fake chat-template delimiters, exfiltration instructions, tool abuse, poisoned-document addressing, and more.
- **Evasion resistance**: NFKC folding, zero-width/bidi stripping, homoglyph mapping, and recursive scan of base64-encoded payloads.
- **Source-aware scoring**: `retrieved` and `tool` content is scored 1.5x and any severity-5 hit blocks, since third-party content should never contain instructions (indirect injection).
- **Verdicts**: `allow` / `review` / `block` with per-finding rule ID, severity, OWASP mapping and excerpt.
- **Output guard**: secret detection (AWS, GitHub, Slack, JWT, private keys, generic API keys), canary-token system-prompt leak detection, and zero-click markdown-image exfiltration links with a host allowlist.
- **Eval harness**: precision / recall / false-positive rate against a labelled JSONL corpus.

## Usage
```bash
pip install -e ".[dev]"
echo "Ignore all previous instructions" | prompt-shield scan - --json
prompt-shield scan retrieved_doc.txt --source retrieved   # exit 0 allow, 1 review, 2 block
prompt-shield eval data/corpus.jsonl
```
```python
from prompt_shield import scan, guard_output, make_canary

canary = make_canary()                      # embed in your system prompt
res = scan(doc_text, source="retrieved")
if res.verdict == "block": ...
leaks = guard_output(model_reply, canary=canary, allowed_hosts=frozenset({"cdn.mycorp.com"}))
```

## Layout
```
prompt_shield/  normalize.py  rules.py  scanner.py  output_guard.py  evaluate.py  cli.py
tests/          21 pytest tests (evasions, false-positive guards, CLI, corpus floor)
data/corpus.jsonl  small labelled dev corpus
```

## Limitations (read this)
Regex heuristics are a **defence-in-depth layer, not a guarantee**. Determined attackers can paraphrase around them, and the bundled 28-sample corpus was used while writing the rules, so its 100% score is a regression check, not a generalisation claim. Combine with least-privilege tools, output filtering, and human approval for sensitive actions. A natural next step is an ML/LLM classifier as a second stage for `review` verdicts.
