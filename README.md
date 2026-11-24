# security-automation-tools

A collection of security automation tools, built incrementally while working
toward incident response / red-blue team roles, alongside applied AI
engineering (RAG, LLM tooling, agentic pipelines).

## Projects

| Project | Description |
|---|---|
| [`prompt-injection-firewall/`](prompt-injection-firewall/) | Source-aware prompt-injection firewall for LLM/RAG/agent pipelines. It undoes obfuscation (zero-width characters, Unicode tag smuggling, homoglyphs, base64), runs a detection-as-code rule pack mapped to OWASP LLM Top 10 (2025) and MITRE ATLAS, and sanitises untrusted content with spotlighting. Output-side canary tokens and DLP catch leaks. An optional LLM judge can only escalate verdicts. Benchmarked on a 63-sample labelled corpus (precision 1.00, recall 0.89) with a CI regression gate. Stdlib-only, 62 tests. |
| [`recon-agent/`](recon-agent/) | Agentic, read-only attack-surface reconnaissance for authorized assessments: a plan-act-observe loop (offline deterministic policy, or LLM-driven tool selection) runs DNS/subdomain enumeration, a concurrent port scan, and an HTTP security-header + TLS certificate audit, then scores findings and writes an executive summary. Stdlib-only core, 39 tests, no real network calls in the test suite. |
| [`log-triage-assistant/`](log-triage-assistant/) | Parses auth-log style syslogs, runs correlated rule-based intrusion detectors (brute force, credential compromise, privilege escalation, persistence), scores overall risk, and produces an incident-response report with an optional LLM-generated analyst narrative grounded strictly in the structured findings. Fully tested with pytest; works offline by default. |
| [`ioc-triage-assistant/`](ioc-triage-assistant/) | Extracts IOCs from raw alerts (with defang handling and false-positive filtering), enriches them against a local threat-intel feed, retrieves relevant MITRE ATT&CK context via a from-scratch TF-IDF/cosine RAG index, and generates a triage summary via an LLM or a deterministic offline fallback. |
| [`process_threat_hunter/`](process_threat_hunter/) | Rule-based process scanner with MITRE ATT&CK mapping, baseline drift detection, JSON reporting, and a pytest suite. A professional rewrite of the earlier `system_logger.py` experiment below. |
| [`port_scanner.py`](port_scanner.py) | Basic TCP connect-scan of common ports using the `socket` library. |
| [`system_logger.py`](system_logger.py) | Early experiment: dumps running processes to a log file and greps them against a static keyword list. Superseded by `process_threat_hunter/`, kept here for history. |

More tools will be added incrementally, each with its own README and tests.
