# security-automation-tools

A collection of security automation projects, built incrementally.

## Projects

- [`ioc-toolkit/`](ioc-toolkit/) — CLI for IR/SOC triage: extracts IOCs
  (IPs, domains, hashes, CVEs, URLs) from threat reports and logs, maps
  offensive-tool mentions to MITRE ATT&CK, and produces a severity-scored
  summary (heuristic by default, optionally Claude-narrated). Tested with
  pytest, CI via GitHub Actions.
- [`port_scanner.py`](port_scanner.py) — basic TCP port scanner (early
  learning project).
- [`system_logger.py`](system_logger.py) — snapshots running processes and
  flags known-suspicious tool names (early learning project).
