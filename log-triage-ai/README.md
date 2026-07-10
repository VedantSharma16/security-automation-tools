# log-triage-ai

A security log triage tool that pairs deterministic, MITRE ATT&CK-mapped
detection rules with an LLM-based analyst layer that turns raw alerts into
an incident summary and a prioritized response plan.

It's built to mirror how a SOC actually works: fast, auditable rules catch
known-bad patterns; a human (or here, Claude) reads the alerts in context
and writes the narrative a responder would act on.

## What it does

1. **Parses** Linux `auth.log`-style SSH and `sudo` events into structured
   `LogEvent` objects.
2. **Detects** three attack patterns via independent, composable rules:
   - **Brute-force login** — N+ failed SSH logins from one IP in a time
     window (`T1110 - Brute Force`)
   - **Credential compromise** — a *successful* login from an IP that just
     failed repeatedly (`T1078 - Valid Accounts`)
   - **Privilege escalation** — `sudo` commands matching known
     escalation/persistence patterns: SUID shells, `/etc/shadow` edits,
     reverse shells, piped `curl | sh` execution, etc.
     (`T1548 - Abuse Elevation Control Mechanism`)
3. **Extracts IOCs** (IPs, domains, URLs, file hashes, emails) from the raw
   log text via regex.
4. **Triages** the resulting alerts into an incident report: overall
   severity, an executive summary, per-alert analyst notes, and concrete
   recommended actions (block an IP, rotate credentials, review sudoers).

## Two triage backends, same interface

Triage is behind a small `TriageClient` protocol so the LLM is optional,
not load-bearing:

- **`HeuristicTriageClient`** (default) — deterministic, offline, no API
  key required. Rolls up alert severities and generates recommended
  actions from the alert types present. This is what runs out of the box
  and what the test suite exercises, so the tool is fully verifiable
  without network access or credentials.
- **`AnthropicTriageClient`** (`--llm`) — sends the structured alert set to
  Claude (`claude-opus-4-8` by default) and asks for a narrative incident
  summary using the API's structured-output mode (`messages.parse` with a
  Pydantic schema), so the response is always valid, typed JSON — not
  prose to re-parse.

```
auth.log --> parser.py --> detectors.py --> triage.py --> report
             (LogEvent)     (Alert, MITRE-      (TriageClient:
                             mapped)              heuristic or Claude)
```

## Usage

```bash
pip install -r requirements.txt

# Offline heuristic triage (no API key needed)
python -m logtriage.cli analyze sample_data/auth.log

# LLM-assisted narrative triage (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
python -m logtriage.cli analyze sample_data/auth.log --llm

# Machine-readable output for piping into other tooling
python -m logtriage.cli analyze sample_data/auth.log --json

# Read from stdin
cat /var/log/auth.log | python -m logtriage.cli analyze -
```

Example output against `sample_data/auth.log`:

```
Parsed 14 log events, 3 alert(s) triggered.

Overall severity: CRITICAL
Summary: 3 alert(s) detected, highest severity 'critical'. Categories: brute_force, credential_compromise, privilege_escalation.

Alerts:
  [HIGH] Brute-force SSH login attempts from 203.0.113.5
    MITRE ATT&CK: T1110 - Brute Force
    Analyst notes: 6 failed login attempts from 203.0.113.5 within 60s.

  [CRITICAL] Successful login from 203.0.113.5 after repeated failures
    MITRE ATT&CK: T1078 - Valid Accounts
    Analyst notes: User 'root' logged in successfully from 203.0.113.5 after 6 failed attempts...

  [HIGH] Suspicious sudo command by root
    MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism
    Analyst notes: SUID bit set on a shell binary: `/bin/chmod 4755 /bin/bash`

Recommended actions:
  - Block or rate-limit source IP 203.0.113.5 at the firewall/WAF.
  - Force a password reset for any accounts that logged in successfully after a failed-login burst...
  - Review sudoers and recently modified SUID binaries; revert unauthorized privilege changes.
  - Preserve the raw log source for this window in case further investigation or legal hold is required.
```

## Project layout

```
log-triage-ai/
  logtriage/
    models.py     # LogEvent, Alert dataclasses
    parser.py      # auth.log line parsing
    detectors.py    # rule-based detection engine (MITRE-mapped)
    ioc.py           # IOC extraction (IPs, domains, hashes, URLs, emails)
    triage.py         # TriageEngine + heuristic/Claude triage backends
    cli.py             # `python -m logtriage.cli`
  sample_data/auth.log  # synthetic log with brute force + privesc + benign noise
  tests/                # pytest suite, no network required
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

The test suite runs entirely offline — it exercises the parser, each
detector individually, IOC extraction, the heuristic triage backend, and
the CLI end-to-end. `AnthropicTriageClient` is intentionally not covered by
automated tests (it would require a live API key and network access); it's
exercised manually via `--llm`.

## Design notes

- **Detectors are independent and composable.** Each one takes a list of
  `LogEvent`s and returns `Alert`s; `run_detectors()` just concatenates
  their output. Adding a new detection rule doesn't require touching
  parsing, triage, or the CLI.
- **The LLM is additive, not required.** A tool that only works with a paid
  API key isn't something a reviewer can easily try. The heuristic backend
  makes the deterministic detection logic — the part that's actually
  auditable in a security context — fully standalone.
- **Structured output, not prose parsing.** `AnthropicTriageClient` uses
  `client.messages.parse()` with a Pydantic schema so the response is a
  validated `TriageReport` object, not a JSON blob hand-parsed out of
  free text.

## Possible extensions

- Additional detectors: impossible-travel geolocation, web server log
  support (SQLi/XSS pattern matching), Windows Event Log parsing.
- A `--watch` mode that tails a live log file and triages in near
  real-time.
- Enrichment lookups for extracted IOCs (e.g. against a local allow/deny
  list or a threat-intel feed).
