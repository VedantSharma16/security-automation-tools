# security-automation-tools

A collection of security automation tools, built incrementally while working
toward incident response / red-blue team roles, alongside applied AI
engineering (RAG, LLM tooling, agentic pipelines).

## Projects

| Project | Description |
|---|---|
| [`log-triage-assistant/`](log-triage-assistant/) | Parses auth-log style syslogs, runs correlated rule-based intrusion detectors (brute force, credential compromise, privilege escalation, persistence), scores overall risk, and produces an incident-response report with an optional LLM-generated analyst narrative grounded strictly in the structured findings. Fully tested with pytest; works offline by default. |
| [`ioc-triage-assistant/`](ioc-triage-assistant/) | Extracts IOCs from raw alerts (with defang handling and false-positive filtering), enriches them against a local threat-intel feed, retrieves relevant MITRE ATT&CK context via a from-scratch TF-IDF/cosine RAG index, and generates a triage summary via an LLM or a deterministic offline fallback. |
| [`process_threat_hunter/`](process_threat_hunter/) | Rule-based process scanner with MITRE ATT&CK mapping, baseline drift detection, JSON reporting, and a pytest suite. A professional rewrite of the earlier `system_logger.py` experiment below. |
| [`websec-posture-scanner/`](websec-posture-scanner/) | Passive web application security scanner: HTTP security headers, cookie flags, CORS misconfiguration, and TLS certificate checks, with A-F grading and text/Markdown/JSON reports. Zero third-party dependencies; fully tested offline against a local `http.server`. |
| [`port_scanner.py`](port_scanner.py) | Basic TCP connect-scan of common ports using the `socket` library. |
| [`system_logger.py`](system_logger.py) | Early experiment: dumps running processes to a log file and greps them against a static keyword list. Superseded by `process_threat_hunter/`, kept here for history. |

More tools will be added incrementally, each with its own README and tests.
