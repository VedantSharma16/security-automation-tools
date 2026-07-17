# security-automation-tools

A collection of security automation projects, ranging from small learning scripts to
fuller tools with tests and docs.

## Projects

- **[log-triage-agent/](log-triage-agent/)** — Parses SSH/sudo auth logs, runs
  deterministic detectors (brute force, account enumeration, privilege escalation)
  mapped to MITRE ATT&CK, and produces an analyst-ready report. The narrative summary
  is pluggable: a template-based summarizer by default, or Claude when
  `ANTHROPIC_API_KEY` is set. Includes a full pytest suite and a synthetic sample log.
- **[port_scanner.py](port_scanner.py)** — Basic TCP connect scanner over a fixed port
  list, built while learning how `socket` works (see [PortScanner_Notes.md](PortScanner_Notes.md)).
- **[system_logger.py](system_logger.py)** — Snapshots running processes and flags any
  matching a list of suspicious tool names (see [system_logger_notes.md](system_logger_notes.md)).

