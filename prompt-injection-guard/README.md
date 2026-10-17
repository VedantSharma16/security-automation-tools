# promptguard — prompt-injection detection for untrusted LLM input

Indirect prompt injection (OWASP LLM01) happens when an attacker hides instructions in content an LLM later reads: a retrieved document, an email, a web page. `promptguard` is a small, dependency-free defensive layer that scans such content **before** it enters a prompt, quarantines hostile chunks, and fences the rest as untrusted data.

## Features

- **12+ rules across 9 categories**: instruction override, role hijack, jailbreak personas, system-prompt exfiltration, fake chat delimiters (`<|im_start|>`, `[INST]`), markdown-image/URL data exfiltration, covert tool use, concealment, authority spoofing.
- **Anti-evasion normalisation**: NFKC, zero-width/bidi stripping, Cyrillic/Greek homoglyph folding, Unicode *tag-character* ASCII smuggling, and base64-wrapped payloads. Findings that only match after de-obfuscation are flagged `obfuscated`.
- **Scoring**: severity-weighted, with a bonus for multi-category hits → `allow` / `review` / `block`.
- **RAG sanitiser**: `sanitize_chunks()` drops (or, in strict mode, quarantines borderline) chunks and wraps survivors in `<untrusted_data>` fences, escaping fence-breakout attempts.
- **Canary tokens**: plant a secret in the system prompt, detect leakage in output (robust to case/separator tricks).
- **Eval harness**: `promptguard eval corpus.jsonl` reports precision/recall; a test enforces a quality gate in CI.

## Usage

```bash
pip install -e ".[dev]"
promptguard scan page.html email.txt          # exit 1 if any file is "block"
promptguard scan --fail-on review --json -    # stdin, stricter gate, JSON output
promptguard eval tests/fixtures/corpus.jsonl
pytest
```

```python
from promptguard import scan, sanitize_chunks, Canary

safe, quarantined = sanitize_chunks([("kb/vpn.md", text1), ("web/x.html", text2)])
prompt_context = "\n".join(safe)           # only vetted, fenced content

canary = Canary()
system = canary.instrument("You are a support bot.")
if canary.leaked(model_reply):
    ...  # prompt extraction succeeded: alert / block the reply
```

## Honest limitations

Heuristics catch known phrasing and common obfuscation, not novel semantic attacks or non-English payloads. The bundled corpus (34 labelled samples) was used to tune the rules, so its 100% precision/recall is a regression gate, **not** a generalisation claim. Treat this as one layer in defence-in-depth alongside privilege separation, output filtering, and human confirmation for sensitive tool calls. A natural extension is an LLM/embedding classifier as a second stage for `review` verdicts.

## Layout

```
promptguard/  normalize.py rules.py scanner.py sanitizer.py canary.py evaluate.py cli.py
tests/        test_promptguard.py, fixtures/corpus.jsonl
```
