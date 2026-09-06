# CodeSec Agent

An agentic static-analysis (SAST) code reviewer for Python codebases. Point
it at a directory and it produces a structured, CWE-mapped vulnerability
report plus an analyst-style narrative review — using a real multi-turn LLM
tool-calling loop when available, and a deterministic offline scan when it
isn't.

## Why this exists

The other tools in this repo show rule-based detection
(`process_threat_hunter/`) and single-shot RAG-grounded summarization
(`ioc-triage-assistant/`). This one demonstrates the piece those don't: an
actual **agentic loop** — the model isn't handed pre-computed context in one
prompt, it decides for itself which files are worth reading, asks a tool to
run static rules against a specific file, greps for patterns it's suspicious
about, and only then writes its review. That's the same tool-use shape used
in real coding agents, applied to a security-review task.

To keep it trustworthy rather than just impressive, the agent's own tool
calls are *not* the source of truth for "what vulnerabilities exist." The
finding list always comes from an independently-computed, deterministic
AST-based scan of the whole tree (`rules.py` + `scanner.py`) — the same
retrieval-grounding principle `ioc-triage-assistant` uses for its RAG
summaries. The LLM narrative is free to explain, prioritize, and add color;
it can't silently omit a vulnerability in a file it never asked to read, and
it can't hallucinate one that isn't there.

## Pipeline

```
                         ┌─────────────────────────────────────────┐
                         │              agent.py                    │
                         │                                           │
  target directory ──────▶  scanner.py: full deterministic AST scan │──▶ findings (ground truth)
                         │       │                                   │
                         │       ▼                                   │
                         │  live? ─── no ──▶ offline templated       │──▶ narrative
                         │   │                narrative from findings│
                         │  yes                                      │
                         │   │                                       │
                         │   ▼                                       │
                         │  tool-calling loop (Claude):               │
                         │   list_python_files / read_file /          │
                         │   run_static_rules / grep_pattern          │──▶ narrative +
                         │   (tools.py, sandboxed to the scan root)   │    tool_calls log
                         └─────────────────────────────────────────┘
                                          │
                                          ▼
                                  report.py: console / markdown / JSON
```

## Detected vulnerability classes

Each rule is an AST-shape check (not a keyword grep), so it can tell
`subprocess.run(["ls"])` (fine) apart from `subprocess.run(cmd, shell=True)`
where `cmd` is dynamic (CWE-78). Ten classes are covered:

| Rule | CWE | Example it catches |
|---|---|---|
| `command-injection` | CWE-78 | `os.system(x)`, `subprocess.run(cmd, shell=True)` with a dynamic command |
| `sql-injection` | CWE-89 | `cursor.execute("... " + user_id)`, f-string queries |
| `insecure-deserialization` | CWE-502 | `pickle.loads(...)`, `yaml.load(...)` without `SafeLoader` |
| `eval-exec` | CWE-95 | `eval(expr)`, `exec(code)` |
| `hardcoded-secret` | CWE-798 | `password = "..."`, AWS access key IDs, secrets in dict/kwarg literals |
| `weak-hash` | CWE-327 | `hashlib.md5(...)`, `hashlib.sha1(...)` |
| `weak-randomness` | CWE-330 | a token/secret built from `random.*` instead of `secrets` |
| `disabled-tls-verification` | CWE-295 | `requests.get(url, verify=False)`, `ssl._create_unverified_context()` |
| `debug-mode-enabled` | CWE-489 | `app.run(debug=True)` |
| `path-traversal` | CWE-22 | `open(filename)` where `filename` is an unvalidated function parameter |

Rules favor precision over recall: `subprocess.run(["ls", "-la"])`,
`yaml.safe_load(...)`, and `hashlib.sha256(...)` all produce zero findings.
See `rules.py` for the full logic and `examples/vulnerable_sample.py` for one
deliberately-vulnerable instance of every class above.

## Quickstart

```bash
cd codesec-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live agentic loop
pytest -q

codesec-agent examples/vulnerable_sample.py
codesec-agent . --min-severity high --json-out report.json
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m codesec_agent.cli examples/vulnerable_sample.py
```

### Enabling the live agentic review

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
codesec-agent . --max-turns 10
```

Without a key, findings are identical (they never depend on the LLM) but the
"Review" section is a deterministic template instead of a model-written
narrative, and no tool calls are made.

### CI usage

```bash
codesec-agent . --fail-on high --json-out sast-report.json
```

Exit codes: `0` clean, `1` a finding at or above `--fail-on` (default
`high`) was found, `2` the path didn't exist. This mirrors
`process_threat_hunter`'s exit-code convention so it slots into the same
kind of CI gate or pre-commit hook.

## Project layout

```
codesec-agent/
├── codesec_agent/
│   ├── rules.py     # AST + regex vulnerability detectors, CWE-mapped
│   ├── scanner.py   # walks a path, runs rules.py over every .py file
│   ├── tools.py     # sandboxed tools the agent can call (list/read/run-rules/grep)
│   ├── agent.py     # the tool-calling loop + offline fallback narrative
│   ├── report.py    # console / markdown / JSON rendering, severity filtering
│   └── cli.py       # argparse CLI with CI-friendly exit codes
├── examples/vulnerable_sample.py   # one vulnerability per rule category
└── tests/           # pytest, fully offline (a fake client tests the tool loop)
```

## Design notes / limitations

- **No dataflow/taint tracking.** Rules match a call's *direct* arguments —
  `cursor.execute("... " + user_id)` is flagged, but
  `q = "... " + user_id; cursor.execute(q)` is not, since that requires
  tracking a value across statements. This is a deliberate scope cut: real
  taint tracking is a project in itself, and a rule that only fires on
  syntactically-obvious cases stays trustworthy enough to gate CI on.
- **`path-traversal` is a narrow heuristic.** It only fires when `open()` is
  called directly on an unvalidated function parameter — it will not catch
  traversal through several layers of helper functions.
- **Findings are always grounded in `scanner.py`, never in the LLM.** This
  is a design choice, not a limitation: it's what makes the live agentic
  mode safe to add without weakening the guarantee that every finding is
  reproducible without any API key.
- **Tool sandboxing is real, not cosmetic.** `tools.py` resolves every path
  argument against the scan root and rejects anything that escapes it
  (`../`, an absolute path elsewhere) — the same class of bug (CWE-22) this
  tool itself flags in code under review.
- **Python only.** The AST rules are Python-specific; extending to another
  language means a different parser and rule set, not a change to the
  agent loop or reporting layer.

## Testing

```bash
pytest -q
```

69 tests cover the rule engine (one test per vulnerability class, plus
false-positive checks for the safe equivalents), the file/directory scanner,
the sandboxed tools (including path-traversal-escape rejection), the
offline agent narrative, the live tool-calling loop (via a small fake
Anthropic client that scripts a multi-turn tool-use conversation), report
rendering, and the CLI's exit codes. No network access or API key is
required to run the suite.
