# Recon Agent

An agentic, read-only attack-surface recon assistant. Given a single
authorized web host, it runs a bounded think-act-observe loop that probes
HTTPS/HTTP/TLS, analyzes the response for common security-header and
transport-security misconfigurations, and produces a prioritized report —
the kind of first pass a pentester or bug-bounty researcher runs before
digging into a target manually.

## Why this exists

The rest of this repo is blue-team detection tooling (log triage, IOC
triage, process hunting). This project fills the pentesting/recon side of
the portfolio, and it's a deliberately different architecture from the
RAG pipeline in `ioc-triage-assistant/`: instead of retrieval + a single
LLM completion, this is a genuine **agent** — a policy that decides, one
step at a time, which tool to call next based on what it has observed so
far, with a bounded loop and a fully offline deterministic fallback so the
agentic pattern itself is testable without any API key or network access.

## Safety and scope

This tool is **passive recon only**:

- Every network action is a single benign HTTP GET or a TLS handshake —
  nothing here brute-forces, fuzzes, injects, or writes anything.
- The agent loop is capped at `--max-steps` (default 6); a broken or
  adversarial policy still terminates rather than scanning indefinitely.
- The CLI refuses to run against a live target unless you pass
  `--i-am-authorized`, an explicit acknowledgement that you have permission
  to assess `--target`. See [`examples/scope.md`](examples/scope.md) for
  the kind of authorization record to keep alongside a real engagement.
- `--fixture` runs the exact same agent loop against canned JSON instead of
  the network, for demos, CI, and offline development — this is how the
  test suite and the example below run, no external host is ever touched.

## How the agent decides what to do next

`recon_agent/agent.py` implements a `ReconAgent` that loops:
`policy(state) -> Action -> execute tool -> record result -> repeat`, until
the policy calls `finish` or `max_steps` is hit. Two policies are provided,
both dispatching through the exact same tool registry (`recon_agent/tools.py`)
so there is only one code path that actually touches the network:

- **`deterministic_next_action`** (default) — a fixed decision tree: probe
  HTTPS, analyze its headers, fall back to HTTP only if HTTPS failed,
  check TLS only if HTTPS succeeded, then finish. Fully offline, fully
  tested.
- **`LLMPolicy`** (`--llm`) — asks an LLM (Anthropic tool use) to choose
  each next step from the same tool set, so it can skip probes that
  clearly won't add signal (e.g. not bothering with a TLS check after
  HTTPS refused the connection). Falls back to the deterministic policy
  automatically if `ANTHROPIC_API_KEY` isn't set or the call fails.

## Findings

- **Header analysis** (`header_analyzer.py`): missing
  `Strict-Transport-Security`/`Content-Security-Policy`/`X-Content-Type-Options`/
  clickjacking protection/`Referrer-Policy`, `Server`/`X-Powered-By` version
  disclosure, cookies missing `Secure`/`HttpOnly`/`SameSite`, and CORS
  misconfiguration (wildcard origin, especially combined with credentials).
- **TLS analysis** (`tls_analyzer.py`): weak negotiated protocol version
  (TLS 1.1 and below), and certificates that are expired or expiring soon.

Each finding carries a severity (`info`/`low`/`medium`/`high`/`critical`),
the evidence that triggered it, and a concrete recommendation.

## Installation

```bash
cd recon-agent
pip install -r requirements.txt        # no dependencies — standard library only
pip install -r requirements-dev.txt    # + pytest, for the test suite
pip install '.[llm]'                   # optional: anthropic, for --llm
```

## Usage

```bash
# Run against the bundled fixture (no network, no authorization flag needed)
python -m recon_agent.cli --target example.com --fixture examples/fixture_example.json

# Real target you are authorized to assess
python -m recon_agent.cli --target app.example-client.com --i-am-authorized

# Only high/critical findings, write JSON + Markdown reports
python -m recon_agent.cli --target example.com --i-am-authorized \
    --min-severity high --json-out report.json --md-out report.md

# Let an LLM drive the step-by-step decisions instead of the fixed sequence
python -m recon_agent.cli --target example.com --i-am-authorized --llm
```

Exit codes: `0` = no findings (after `--min-severity` filtering),
`1` = findings reported, `2` = a fatal error (bad args, missing fixture).

## Project layout

```
recon-agent/
├── recon_agent/
│   ├── models.py          # ProbeResult, TLSResult, Finding, AgentStep
│   ├── http_probe.py       # GET + TLS handshake probes (stdlib only)
│   ├── header_analyzer.py  # security-header rule set
│   ├── tls_analyzer.py     # TLS version + cert-expiry rule set
│   ├── tools.py            # tool registry shared by both policies
│   ├── agent.py            # AgentState, policies, the bounded loop
│   ├── fixtures.py         # canned-data mode for offline/demo runs
│   ├── report.py           # console + Markdown + JSON rendering
│   └── cli.py              # argparse entry point
├── examples/
│   ├── fixture_example.json
│   └── scope.md            # example authorization record
├── tests/
└── requirements.txt / requirements-dev.txt
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

61 tests cover header/TLS rule logic, the tool registry, the deterministic
policy's decision tree (including the bounded-loop safety property), report
rendering, and the CLI — all offline. `http_probe.py`'s GET path is tested
against a local `127.0.0.1` server; its TLS path is tested with a mocked
socket, so no real external host is ever touched by the suite.

## Possible extensions

- Subdomain enumeration as an additional tool, gated behind the same
  authorization flag.
- A second LLM pass that turns the structured findings into a narrative
  executive summary, mirroring `log-triage-assistant`'s approach.
- Rate limiting / concurrency controls for assessing many hosts in one
  authorized scope.
