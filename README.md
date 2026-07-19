# security-automation-tools

A growing collection of security automation projects, spanning classic
blue/red-team tooling and AI-assisted security workflows.

## Projects

- **[log-triage-assistant](./log-triage-assistant)** — parses auth-log style
  syslogs, runs rule-based intrusion detectors (brute force, credential
  compromise, privilege escalation, persistence), and produces an
  incident-response report with an optional LLM-generated analyst narrative.
  Fully tested with pytest; works offline by default.
- **`port_scanner.py`** — a minimal TCP connect scanner for a fixed set of
  common ports.
- **`system_logger.py`** — a script that snapshots basic system info and
  running processes and flags any matching a configurable keyword list.

More tools will be added incrementally, each with its own README and tests.

