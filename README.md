# security-automation-tools

A growing collection of security automation projects — built while learning,
now moving toward production-quality structure, tests, and docs per project.

## Projects

- [`log-sentinel/`](log-sentinel/) — SSH auth-log anomaly detector (brute
  force, credential compromise, account enumeration, off-hours logins) with
  an optional Claude-generated incident report. Rule-based detection engine,
  provider-abstracted report generator, full pytest suite.

## Early scripts

The scripts below were early learning exercises and are kept for history:

- `port_scanner.py` — basic TCP connect scanner (see `PortScanner_Notes.md`)
- `system_logger.py` — process listing with a suspicious-keyword check (see
  `system_logger_notes.md`)

