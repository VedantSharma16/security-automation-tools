# SOC Agent — Agentic Alert Investigator

A small **agentic** SOC investigator: given a raw security alert, it runs a
tool-calling (ReAct-style) loop that decides *for itself* which tools to
call — IP/domain reputation, WHOIS age, GeoIP, process baseline, ATT&CK
technique search — reads back each observation, and keeps going until it
has enough evidence to reach a verdict. The full step-by-step trace
(thought → action → observation) ships with every result, so the reasoning
is auditable, not just the conclusion.

It's the multi-step counterpart to this repo's other AI-assisted tools:
[`ioc-triage-assistant/`](../ioc-triage-assistant/) and
[`log-triage-assistant/`](../log-triage-assistant/) are single-pass
pipelines (extract → enrich → one LLM summarization call). This project is
the one that actually *acts* — the model chooses its own tool calls,
observes their results, and can call more tools before answering.

## Why this exists

"Agentic pipeline" demos often either (a) hide the loop behind a framework
so the actual control flow isn't visible, or (b) fake it with a single LLM
call that lists steps it didn't really take. This project keeps the loop
itself small and inspectable, and — like the rest of this repo — fully
runnable offline:

- **Live mode** runs a real Claude tool-calling loop
  (`soc_agent/llm_client.py::run_live_agent`): the model reads the alert,
  emits `tool_use` blocks, gets back real tool results, and iterates for up
  to `--max-steps` turns before returning a structured JSON verdict.
- **Offline mode** (`soc_agent/agent.py::_run_offline_agent`) is a
  deterministic fallback that calls the *exact same tool functions* in a
  fixed but still multi-step plan, producing an identically shaped trace.
  No API key or network access is needed to run the tool, the demo, or the
  test suite — including the tests that exercise the live tool-calling loop
  itself, via a scripted fake of the `anthropic` SDK
  (`tests/fake_anthropic.py`) so the loop's control flow is verified without
  ever making a real network call.
- **Tool schemas are defined once** (`soc_agent/tools.py::TOOL_SCHEMAS`) in
  Anthropic tool-use / JSON-Schema form and reused by both brains — there's
  no separate hand-maintained list of "what the model can call."

## How the loop works

```
alert text
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  live: Claude decides which tool to call next             │
│  offline: fixed plan calls the same tools in sequence     │
└─────────────────────────────────────────────────────────┘
     │              tool_use / action
     ▼
┌─────────────────────────────────────────────────────────┐
│  tools.py: lookup_ip_reputation / lookup_domain_reputation │
│  geoip_lookup / whois_lookup / check_process_baseline      │
│  search_attack_techniques                                  │
└─────────────────────────────────────────────────────────┘
     │              observation (JSON)
     ▼
   fed back into the loop — repeat until enough evidence
     │
     ▼
 final verdict: verdict / severity / confidence / summary /
                recommended_actions, with the full trace attached
```

## Tools available to the agent

| Tool | What it checks |
|---|---|
| `lookup_ip_reputation` | Local threat-intel feed for a known-malicious/suspicious IP |
| `lookup_domain_reputation` | Local threat-intel feed for a known-malicious/suspicious domain |
| `geoip_lookup` | Coarse geolocation + ASN/hosting provider for an IP |
| `whois_lookup` | Domain registration age — freshly registered domains are a strong phishing/C2 signal |
| `check_process_baseline` | Whether a process name is known-good, known-bad (e.g. `mimikatz.exe`), or unrecognized |
| `search_attack_techniques` | Keyword search over a curated MITRE ATT&CK technique subset |

All backing data in `data/*.json` is a small **synthetic** dataset for the
demo (see each file's `_comment` field) — not live threat intelligence. Each
`tools.py` function is the seam to swap in a real feed (MISP, OTX,
VirusTotal, a real WHOIS/GeoIP API) without touching the agent loop.

## Quickstart

```bash
cd soc-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live Claude agent
pytest -q

soc-agent --file examples/sample_alert.txt
soc-agent --file examples/sample_alert.txt --json
soc-agent --file examples/sample_alert.txt --no-trace   # verdict only, no step-by-step trace
echo "Beacon to 185.220.101.1 observed." | soc-agent
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m soc_agent.cli --file examples/sample_alert.txt
```

### Enabling the live agent

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
soc-agent --file examples/sample_alert.txt --max-steps 8
```

Without a key, the CLI reports `Agent brain: offline deterministic (no API
key)` and still runs the full multi-tool investigation — the offline agent
isn't a stub, it makes the same tool calls a live run would, just via a
fixed plan instead of model-driven decisions.

## Example output

Running against `examples/sample_alert.txt` (a synthetic EDR alert:
encoded PowerShell spawned by Word, a persistence scheduled task, and
beaconing to a known-malicious domain/IP):

```
☠️ Verdict: MALICIOUS   🔴 Severity: CRITICAL   Confidence: high
Agent brain: offline deterministic (no API key)

Investigation trace (10 step(s)):
  [1] Thought: Scanned the alert text and extracted 2 IP(s), 1 domain(s), and 2 process name(s) to investigate.
      Action: extract_seed_indicators({})
      Observation: {'ips': ['45.155.205.38', '185.220.101.1'], 'domains': ['update-service-cdn.net'], 'processes': ['powershell.exe', 'winword.exe']}
  [2] Thought: Checking threat-intel reputation for IP 45.155.205.38.
      Action: lookup_ip_reputation({'ip': '45.155.205.38'})
      Observation: {'ip': '45.155.205.38', 'verdict': 'malicious', 'confidence': 'high', ...}
  ...
  [8] Thought: Checking process powershell.exe against the known-good/known-bad baseline.
      Action: check_process_baseline({'process_name': 'powershell.exe'})
      Observation: {'process_name': 'powershell.exe', 'status': 'known_bad', ...}
  [10] Thought: Searching the ATT&CK reference for techniques matching the observed behavior.
      Action: search_attack_techniques({'query': 'powershell.exe winword.exe'})
      Observation: [{'id': 'T1059', 'name': 'Command and Scripting Interpreter', ...}]

Summary:
  Confirmed malicious indicators observed: ip 45.155.205.38, ip 185.220.101.1, domain
  update-service-cdn.net. Known-bad tooling observed on the host: powershell.exe. Behavior
  most closely resembles ATT&CK T1059 (Command and Scripting Interpreter, Execution).

Recommended actions:
  - Isolate the affected host(s) from the network pending further investigation.
  - Pivot on the flagged indicators across EDR/SIEM to scope related activity.
  - Capture a memory/process dump before killing the flagged process for forensic review.
```

## Project layout

```
soc-agent/
├── soc_agent/
│   ├── extractor.py    # seed indicator extraction (IPs/domains/processes) from raw alert text
│   ├── tools.py         # tool implementations + Anthropic tool-use schemas (single source of truth)
│   ├── llm_client.py    # live Claude tool-calling (ReAct) loop
│   ├── agent.py          # orchestration: picks live vs offline brain, offline deterministic agent
│   ├── report.py         # human-readable / JSON rendering of an InvestigationResult
│   └── cli.py              # argparse CLI
├── data/                  # synthetic offline threat-intel / WHOIS / GeoIP / baseline / ATT&CK datasets
├── examples/sample_alert.txt
└── tests/
    ├── fake_anthropic.py  # scripted fake of the anthropic SDK for testing the live loop offline
    └── test_*.py
```

## Design notes / limitations

- **All threat-intel/WHOIS/GeoIP data is synthetic**, sized for a readable
  demo. The tool functions are the integration seam for real data sources.
- **The offline agent's plan is fixed** (extract → check each indicator →
  search ATT&CK → synthesize), while the live agent's plan is genuinely
  model-driven — it can skip tools, call them in a different order, or call
  the same tool for a different indicator the offline plan wouldn't think
  to check. They're deliberately not identical; the offline path exists so
  the tool is fully usable and testable without an API key, not to fully
  replicate the model's judgment.
- **`search_attack_techniques` uses simple token-overlap scoring**, not a
  vector index — the retrieval logic is a few readable lines, at the cost
  of missing synonyms a real embedding-based retriever would catch. See
  `ioc-triage-assistant/` in this repo for a from-scratch TF-IDF/cosine RAG
  implementation if that tradeoff matters for a given use case.
- **Step budget, not a hard timeout.** `--max-steps` bounds tool calls, not
  wall-clock time. If the live agent exhausts its budget without a parsed
  final answer, `agent.py` synthesizes a best-effort verdict from whatever
  evidence it gathered and flags the summary accordingly, rather than
  failing the investigation outright.

## Testing

```bash
pytest -q
```

42 tests cover indicator extraction, each tool function (including
synthetic-data edge cases like unknown IPs/domains), the offline agent's
full investigation plan and verdict synthesis, report rendering, and the
CLI (as a subprocess, human/JSON/no-trace/stdin/empty-input paths). The
live tool-calling loop itself — including step-budget exhaustion and
unknown-tool-name handling — is unit tested against a scripted fake of the
`anthropic` SDK, so no network access or API key is required to run the
suite.
