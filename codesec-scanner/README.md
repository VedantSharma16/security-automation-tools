# codesec

A command-line static application security testing (SAST) tool for Python
codebases. It finds hardcoded secrets and known-insecure coding patterns,
and can gate a CI pipeline on the result — optionally with an LLM-written
remediation narrative on top.

It follows the same design principle as this repo's other triage tools:
**detection stays deterministic and auditable; the LLM only writes prose on
top of findings the rules already produced.** The model never sees raw
source and is explicitly instructed not to invent findings beyond the
structured JSON it's given.

## What it detects

**Hardcoded secrets** (regex + Shannon-entropy, works on any text file):

| Rule | Example |
|---|---|
| AWS access key / secret key | `AKIA...`, `aws_secret_access_key = "..."` |
| GitHub / Slack tokens | `ghp_...`, `xoxb-...` |
| Private key material | `-----BEGIN RSA PRIVATE KEY-----` |
| JWTs | `eyJhbGciOi...` |
| Generic credential assignment | `password = "..."`, `db_password = "..."`, `API_KEY = "..."` |
| High-entropy string (no known format) | any long, high-entropy quoted literal |

**Insecure code patterns** (AST-based, Python only — reasons about actual
call targets and keyword arguments, not just text):

| Rule | CWE | Example |
|---|---|---|
| SQL injection | CWE-89 | `cursor.execute(f"... {username}")` |
| OS command injection | CWE-78 | `os.system(...)`, `subprocess.run(cmd, shell=True)` |
| `eval()` / `exec()` | CWE-95 | `eval(expr)` |
| Insecure deserialization | CWE-502 | `pickle.loads(...)`, `yaml.load(x, Loader=yaml.Loader)` |
| Weak hash for passwords | CWE-327 | `hashlib.md5(password)` |
| Predictable randomness for secrets | CWE-330 | `token = random.random()` |
| Disabled TLS verification | CWE-295 | `requests.get(url, verify=False)` |
| Debug mode enabled | CWE-489 | `app.run(debug=True)` |

Command-injection severity is escalated to CRITICAL specifically when the
shell command is built from a non-literal expression (e.g. string
concatenation of a parameter) rather than a fixed string literal, since
that's the case that's actually exploitable.

## Install

```bash
cd codesec-scanner
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered remediation narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
codesec scan path/to/file_or_directory
codesec scan . --format json --out report.json
codesec scan . --llm                        # use Claude for the remediation narrative

# CI gate: exit 1 if anything HIGH or above is found
codesec scan . --fail-on HIGH
```

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic, offline template advisor — the tool is always usable
without any API key or network access.

Try it against the included, deliberately vulnerable example:

```bash
codesec scan examples/vulnerable_app.py
```

## Architecture

```
codesec/
  entropy.py          Shannon-entropy helpers for the secrets scanner
  secrets_scanner.py   regex + entropy detectors, language-agnostic file walk
  ast_scanner.py       ast.NodeVisitor-based detectors for insecure Python patterns
  findings.py          Finding / Severity / ScanResult data model
  report.py            ScanResult -> text or JSON report
  llm_advisor.py        report dict -> remediation narrative (TemplateAdvisor or AnthropicAdvisor)
  cli.py                argparse entry point wiring the above together, incl. the CI --fail-on gate
```

Each stage takes the previous stage's output and nothing else, so every
piece is independently unit-testable — see `tests/`, which covers the
entropy heuristics, both detectors (including true/false-positive cases),
report rendering, the advisor fallback logic, and the CLI end-to-end.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## Why AST instead of regex for code patterns

Regex-over-source is what most quick "grep for `eval(`" scanners do, and it
is both noisy and easy to evade — it can't tell `# eval(x) is dangerous` in
a comment from a real call, and it can't see keyword arguments like
`shell=True` or `verify=False`. Parsing to an AST and walking `Call` nodes
means every rule reasons about the actual function being called and its
actual arguments, which is what real SAST tools (Bandit, Semgrep) do under
the hood. Secrets, by contrast, need to work on non-Python files too
(`.env`, YAML, config files), so that detector stays regex/entropy-based by
necessity.
