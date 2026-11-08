# promptshield

Offline **prompt-injection detector** and **RAG context gate** for LLM applications, with a labeled
evaluation harness. Stdlib only; no network or API key required.

Prompt injection is #1 in the OWASP Top 10 for LLM Applications (LLM01). Agents that read untrusted
content (web pages, emails, retrieved documents) are exposed to *indirect* injection, so this tool
scans both user input and retrieved documents before they reach the model.

## How it works

1. **Normalize** (`normalize.py`) – strips zero-width/bidi characters, applies NFKC, folds common
   Cyrillic/Greek homoglyphs, and decodes natural-language base64 blobs so hidden payloads get scanned.
2. **Rules** (`rules.py`) – 11 readable regex rules (instruction override, role hijack, jailbreak
   framing, system-prompt leak, chat-template delimiter spoofing, exfiltration via markdown image/URL/email,
   tool abuse, indirect "note to the AI", secrecy, decode-then-obey), each mapped to an OWASP LLM category.
3. **Score** (`scanner.py`) – 0–100 with diminishing returns per extra rule; obfuscation adds weight.
   Verdicts: `clean` (<35), `suspicious` (35–69), `block` (≥70).
4. **RAG gate** (`rag.py`) – per-document `allow` / `redact` (normalized and wrapped in an
   `<untrusted_document>` fence) / `quarantine`.
5. **Evaluate** (`evaluate.py`) – precision/recall/F1 over `corpus.json` (20 attacks, 18 benign
   including tricky look-alikes such as "ignore phishing emails").

## Usage

```bash
pip install -e .[dev]
promptshield scan suspicious.txt --json     # exit code 0 clean / 1 suspicious / 2 block
echo "Ignore all previous instructions" | promptshield scan -
promptshield eval
pytest
```

```python
from promptshield import Scanner, sanitize_documents
Scanner().scan(user_text).verdict
safe_ctx = [d.text for d in sanitize_documents(retrieved) if d.action != "quarantine"]
```

## Limitations (read before trusting it)

- Heuristic and English-centric; a determined attacker can paraphrase around regexes. Treat it as one
  layer (alongside least-privilege tools, output filtering, and human approval), not a guarantee.
- The bundled corpus is small and the rules were tuned against it, so the 1.0 F1 is optimistic. Extend
  `corpus.json` with held-out samples to measure real-world performance.
