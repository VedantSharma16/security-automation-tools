# ragshield — indirect prompt-injection defence for RAG pipelines

Retrieved documents are untrusted input. A poisoned web page, PDF, or wiki entry
can carry instructions ("ignore previous instructions…", hidden markdown-image
exfiltration, base64-encoded payloads) that an LLM may obey. **ragshield** scans
chunks *before* prompt assembly, scores them, and sanitises or drops the bad ones.
Maps to **OWASP LLM01: Prompt Injection**. Stdlib-only, no network, no API keys.

## How it works

```
chunk -> normalize -> rules -> score -> verdict -> gate (pass / sanitize / drop)
```

1. **Normalisation** defeats evasion: strips zero-width/bidi characters, NFKC-folds,
   maps Cyrillic/Greek look-alikes to ASCII, and decodes base64 blobs. Each evasion
   technique observed is itself a risk signal.
2. **Ten explainable rules** (`ragshield/rules.py`): instruction override, role hijack,
   prompt exfiltration, fake chat delimiters, data exfiltration, tool abuse,
   AI-addressed text, secrecy demands, output forcing, authority claims.
3. **Scoring** (0–100): top finding dominates with diminishing returns for extras;
   hits in hidden channels (base64, HTML comments) and evasion add weight.
   `>=70` block, `>=30` quarantine, else allow.
4. **Gate**: `allow` → fenced as `<untrusted>` data; `quarantine` → matched spans redacted
   (or dropped); `block` → dropped. Fence break-out attempts are neutralised.

## Usage

```bash
pip install -e .[dev]
ragshield scan samples                 # human-readable
ragshield scan docs/ --json            # machine-readable
ragshield scan docs/ --fail-on quarantine   # CI gate: exit 1 on findings
cat page.html | ragshield scan -
```

```python
from ragshield import gate_chunks
for d in gate_chunks({"doc1": text1, "doc2": text2}):
    if d.text: prompt_parts.append(d.text)      # safe, fenced content
    else: log.warning("dropped %s: %s", d.chunk_id, d.result.findings)
```

Example (`samples/poisoned_faq.md`): a hidden HTML comment telling the model to
redirect payments and conceal it → `BLOCK score=100`, findings tagged `html-comment`.

## Tests

`python -m pytest` — 25 tests covering every rule, evasion techniques, false-positive
guards on benign text, sanitiser, fence break-out, gate policies, and CLI exit codes.

## Limitations

Pattern-based detection is a first layer, not a guarantee: paraphrased or
non-English attacks can slip through. Pair it with least-privilege tool access,
output filtering, and human approval for sensitive actions. A natural extension is
an LLM/classifier second pass for the `quarantine` band.
