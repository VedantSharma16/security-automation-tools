# log-sentinel

SSH auth-log anomaly detection with AI-assisted incident reporting.

`log-sentinel` parses OpenSSH auth logs, runs a small set of rule-based
detections a blue teamer would actually reach for (brute force, credential
compromise, account enumeration, off-hours logins), and turns the results
into a Markdown incident report — either with a deterministic offline
template or, optionally, with Claude for analyst-ready prose.

## Why this exists

It's a small, complete slice of the incident-response workflow: **parse →
detect → report**, built to show both sides of the target role — practical
blue-team log analysis, and an AI-assisted reporting layer with a clean
provider abstraction (the kind of thing an "LLM feature" looks like in a
real product, not a notebook demo).

## Detections

| Finding | Trigger | Severity |
|---|---|---|
| `BRUTE_FORCE` | N+ failed logins from one IP within a sliding time window | high / critical |
| `CREDENTIAL_COMPROMISE_SUSPECTED` | A successful login from an IP that also failed at least once | medium / critical |
| `USER_ENUMERATION` | N+ distinct nonexistent usernames probed from one IP | medium |
| `ANOMALOUS_LOGIN_TIME` | Successful login outside a configured business-hours window | low |

Findings that reasonably map to a MITRE ATT&CK technique are labeled with
it (e.g. brute force → T1110) — kept conservative, no ID is cited unless it
clearly applies.

## Install

```bash
cd log-sentinel
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"      # add "[llm]" too if you want the Claude-backed report
```

## Usage

```bash
log-sentinel sample_data/auth.log
```

```markdown
# Incident Report: sample_data/auth.log

**Summary:** 4 finding(s) — 1 critical, 1 medium, 1 low, 1 ...

## 🔴 BRUTE_FORCE — 203.0.113.55 (critical)

7 failed SSH authentication attempts from 203.0.113.55 targeting 5 account(s)
(admin, oracle, postgres, root, test) within a 60s window.

- **Window:** 2026-07-14T03:14:01 → 2026-07-14T03:14:23
- **Events:** 7
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Recommended action:** Block or rate-limit the source IP, enforce account
  lockout / fail2ban, and require key-based SSH authentication instead of
  passwords.
...
```

Useful flags:

```bash
# JSON output for piping into another tool / SIEM
log-sentinel sample_data/auth.log --format json

# tune detection thresholds
log-sentinel /var/log/auth.log --brute-force-threshold 8 --window 30

# exit non-zero when something at/above a severity is found (CI/cron friendly)
log-sentinel /var/log/auth.log --fail-on critical

# generate the report with Claude instead of the offline template
export ANTHROPIC_API_KEY=sk-...
log-sentinel sample_data/auth.log --use-llm
```

`--use-llm` degrades gracefully: if the `anthropic` package isn't
installed or `ANTHROPIC_API_KEY` isn't set, it falls back to the offline
template report with a warning on stderr, rather than failing the scan.

## Architecture

```
src/log_sentinel/
  parser.py    # regex-based OpenSSH syslog line parser -> LogEntry
  detector.py  # rule-based detection over LogEntry lists -> Finding
  report.py    # Finding list -> Markdown (template or Claude-backed)
  cli.py       # argparse CLI wiring the three stages together
```

Each stage is a pure function/class over plain data, so the detector and
report generator are independently unit-testable without touching the
filesystem or the network.

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```

Tests cover the parser (line formats, malformed input), the detector
(threshold/window edge cases for every rule), the report generator
(including the LLM-unavailable fallback path, exercised without needing an
API key), and the CLI end-to-end against `sample_data/auth.log`.

## Limitations / roadmap

- Detection is single-pass over a static log file; there's no streaming/tail
  mode yet.
- No IP geolocation or "impossible travel" check — would be a natural next
  rule.
- `sample_data/auth.log` is synthetic, using RFC 5737 documentation IP
  ranges (`203.0.113.0/24`, `198.51.100.0/24`) — safe to use in examples.

## Disclaimer

Built for defensive/educational use: analyzing logs you own or are
authorized to review. It does not perform any active scanning or exploitation.
