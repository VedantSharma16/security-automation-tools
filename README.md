# security-automation-tools

A collection of security automation tools, built incrementally while working
toward incident response / red-blue team roles.

## Projects

| Project | Description |
|---|---|
| [`process_threat_hunter/`](process_threat_hunter/) | Rule-based process scanner with MITRE ATT&CK mapping, baseline drift detection, JSON reporting, and a pytest suite. A professional rewrite of the earlier `system_logger.py` experiment below. |
| [`port_scanner.py`](port_scanner.py) | Basic TCP connect-scan of common ports using the `socket` library. |
| [`system_logger.py`](system_logger.py) | Early experiment: dumps running processes to a log file and greps them against a static keyword list. Superseded by `process_threat_hunter/`, kept here for history. |

