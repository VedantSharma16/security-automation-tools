# security-automation-tools

A collection of security automation projects, built up over time as I move
into incident response / pentesting / blue-red team roles while also
building out AI engineering skills (RAG, agentic pipelines, LLM tooling).

## Projects

- **[log-triage-agent](log-triage-agent/)** — parses SSH auth logs, detects
  brute force / password spray / compromised-credential patterns, maps each
  detection to MITRE ATT&CK via a local retrieval step, and generates an
  incident report (with optional LLM-generated narrative enrichment). The
  most complete project here: full test suite, pluggable retrieval and
  generation layers, zero required dependencies.
- **[port_scanner.py](port_scanner.py)** — a basic TCP connect scanner over
  a fixed set of common ports, using Python's `socket` module.
- **[system_logger.py](system_logger.py)** — snapshots system info and
  running processes to a log file and flags any process names matching a
  configurable list of suspicious keywords (`suspicious_keywords.txt`).

