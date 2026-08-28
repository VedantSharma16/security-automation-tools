# Web Recon Agent

A small **ReAct-style agentic pipeline** for authorized web-application
reconnaissance: instead of a fixed script, an agent loop repeatedly decides
*which lightweight recon tool to run next* based on what it has already
observed, until it has enough information to stop — then produces a
risk-scored findings report with an analyst-facing narrative.

It ships with a fully deterministic, offline planner (so the tool and its
test suite need no API key or network access to prove correctness), and an
optional dynamic planner that hands the same tool set to Claude via
tool-use, so the model itself decides the recon path.

## Why this exists

Most "AI recon tool" demos either hard-code a linear pipeline and bolt an
LLM onto the end for a summary, or wrap an LLM prompt around a scanner with
no visible reasoning loop. This project keeps the actual **agent mechanics**
visible and testable:

- **A real plan → act → observe loop** (`agent.run_agent`), not a fixed
  sequence of function calls. The planner sees the transcript so far and
  decides the next tool call — or that it's done.
- **Two interchangeable planners behind one interface.** `DeterministicPlanner`
  encodes the same conditional logic a human analyst would follow (skip TLS
  inspection on plain HTTP, only grade headers if the fetch actually
  succeeded, scan the target's own port alongside common ones). `LLMPlanner`
  hands Claude the identical tool schemas and lets it choose dynamically —
  a genuine dynamic agent, not a scripted one with an LLM label on it.
- **Every network call is injectable.** `ToolBox` takes `http_get`,
  `resolve`, `tcp_connect`, and `tls_info` as constructor arguments, so the
  full agent loop — dynamic branching included — is exercised in tests with
  fakes, and the CLI test suite drives a real (loopback-only) HTTP server
  instead of mocking away the interesting parts.
- **LLM usage is optional everywhere**, matching the rest of this repo:
  without `ANTHROPIC_API_KEY`, the CLI still runs the full agent loop and
  produces a complete, structured report via a templated offline narrative.

## Scope and safety

This is a **passive/lightweight recon** tool, not a scanner or exploitation
framework:

- No exploitation, brute forcing, fuzzing, or credential attempts.
- The port scan is a plain TCP-connect check against a short, curated list
  of common service ports (plus the target's own port) — not a full range
  sweep.
- The CLI refuses to run against any non-local target unless you pass
  `--i-am-authorized`, as a deliberate reminder that active recon requires
  explicit authorization even when every individual check is low-impact.

## Agent loop

```
target URL
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│ run_agent(target, toolbox, planner, max_steps)           │
│                                                           │
│   loop:                                                  │
│     action = planner.plan(step, transcript)  ── Finish? ─┼──► stop
│     result = toolbox.<action.tool>(**action.kwargs)      │
│     transcript.append(step, action, result)              │
└─────────────────────────────────────────────────────────┘
     │
     ▼
report.collect_findings()  ── per-tool heuristics → Finding(category, severity, summary)
     │
     ▼
report.overall_severity()  ── weighted severity roll-up (low/medium/high/critical)
     │
     ▼
llm_client.Narrator        ── Claude narrative, or a deterministic offline summary
     │
     ▼
ReconReport (human-readable or JSON)
```

**Tools available to the planner:** `dns_lookup`, `fetch_headers`,
`grade_security_headers`, `fetch_robots_txt`, `check_tls`, `port_scan`, and
`finish`.

**`DeterministicPlanner`'s sequence** (with its branches): resolve host →
fetch headers → grade headers *(only if the fetch succeeded)* → check
robots.txt → inspect TLS *(only if the target is HTTPS)* → port-scan common
ports plus the target's own port → finish.

## Quickstart

```bash
cd web-recon-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for a live Claude planner/narrative
pytest -q

# Local targets don't need an authorization flag:
recon-agent http://localhost:8000

# Any other target requires an explicit authorization confirmation:
recon-agent https://example.com --i-am-authorized
recon-agent https://example.com --i-am-authorized --json
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m recon_agent.cli http://localhost:8000
```

### Enabling the dynamic (Claude-driven) planner

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
recon-agent https://example.com --i-am-authorized --llm-planner
```

Without a key, `--llm-planner` prints a warning to stderr and transparently
falls back to `DeterministicPlanner` — the run still completes.

## Example output

Run against a local server with default (missing) security headers:

```
🔴 Overall risk: CRITICAL
Planner: DeterministicPlanner
LLM-backed narrative: no (offline heuristic fallback)
Finished: All planned recon steps are complete.

Steps performed:
  - dns_lookup: ok
  - fetch_headers: ok
  - grade_security_headers: ok
  - fetch_robots_txt: ok
  - port_scan: ok

Findings (6):
  - [low] info_disclosure: Server header discloses software/version: 'SimpleHTTP/0.6 Python/3.11.15'
  - [high] security_headers: Missing or weak 'Content-Security-Policy' response header.
  - [medium] security_headers: Missing or weak 'X-Content-Type-Options' response header.
  - [medium] security_headers: Missing or weak 'X-Frame-Options' response header.
  - [low] security_headers: Missing or weak 'Referrer-Policy' response header.
  - [low] security_headers: Missing or weak 'Permissions-Policy' response header.

Narrative:
[offline heuristic narrative — set ANTHROPIC_API_KEY for LLM-generated analysis] Overall risk: CRITICAL. ...
```

## Project layout

```
web-recon-agent/
├── recon_agent/
│   ├── tools.py             # ToolBox: dns/http/tls/port-scan primitives, all injectable
│   ├── security_headers.py  # pure header-hardening grading logic
│   ├── planner.py           # AgentAction/Finish + DeterministicPlanner + LLMPlanner
│   ├── agent.py             # the plan -> act -> observe loop
│   ├── report.py            # transcript -> Finding list -> severity -> ReconReport
│   ├── llm_client.py        # Claude narrative + offline fallback
│   ├── _anthropic_util.py   # shared "do we have a usable Claude client" check
│   └── cli.py                # argparse CLI + authorization gate
└── tests/                    # pytest, fully offline (loopback HTTP server for CLI tests)
```

## Design notes / limitations

- **Severity scoring is a heuristic, not a verdict** — the same philosophy
  as this repo's other triage tools. It's a weighted sum over finding
  severities meant to prioritize an analyst's attention, not a compliance
  statement.
- **The port list is intentionally short.** `tools.COMMON_PORTS` covers ten
  frequently-exposed services; this is a recon aid, not a substitute for a
  proper scanner (nmap, masscan) when a full sweep is actually authorized
  and needed.
- **TLS certificate parsing assumes a standard `getpeercert()` shape.**
  Self-signed certificates behind `ssl.create_default_context()` will fail
  the handshake by design (no `CERT_NONE` override) — that failure is
  itself surfaced as a `tls` finding rather than silently ignored.
- **The LLM planner is stateless per call** — it re-reads the full
  transcript each step rather than maintaining server-side conversation
  state, so it can be swapped out or resumed without extra bookkeeping.

## Testing

```bash
pytest -q
```

46 tests cover security-header grading, every tool's success/failure paths
(via injected fakes), the deterministic planner's branching logic, the
`LLMPlanner`'s tool-use parsing (via a fake Anthropic client, no network or
key required), the full agent loop (including max-step cutoff and
unknown-tool/bad-argument handling), finding collection and severity
roll-up, and the CLI end-to-end against a real local HTTP server on
loopback. No external network access or API key is required to run the
suite.
