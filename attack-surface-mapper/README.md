# attack-surface-mapper

Turns a raw `nmap` scan into a prioritized, pentest-style report: parse the
scan, correlate every open service against a local CVE / insecure-protocol
rule database, score and rank the results, and (optionally) hand the
structured findings to an LLM to write the analyst narrative.

This is the offensive-security counterpart to this repo's other triage
tools: `log-triage-assistant` and `process_threat_hunter` analyze what
already happened on a host; `ioc-triage-assistant` triages inbound alerts;
`attack-surface-mapper` looks at a target from the outside, the way a
pentester scoping an engagement would.

## Why this design

- **Grounded, not generative.** The CVE/version correlation is deterministic
  rule-matching against a curated local database, not an LLM guessing which
  CVEs apply. The LLM (when enabled) only narrates findings that were
  already verified structurally -- it never invents a host, port, or CVE.
- **Confidence-aware.** A service nmap fingerprinted without a version
  string (common when banners are suppressed or scans are `-sV`-light)
  still produces a match, but flagged `unconfirmed` and scored lower, so it
  surfaces for manual review instead of disappearing or being reported as
  fact.
- **Offline by default.** No network calls, no API key required. `--llm`
  is opt-in and gracefully falls back to a deterministic template narrator
  if `anthropic` isn't installed or `ANTHROPIC_API_KEY` isn't set.

## Install

```bash
cd attack-surface-mapper
pip install -e ".[dev]"       # add ",llm" too if you want --llm
```

## Usage

```bash
# Generate a Markdown report from an nmap XML scan (nmap -oX scan.xml ...)
asm scan examples/sample_scan.xml

# JSON output, written to a file
asm scan examples/sample_scan.xml --format json --out report.json

# Use a custom rule database
asm scan scan.xml --cve-db my_rules.json

# Let Claude write the narrative section (requires ANTHROPIC_API_KEY)
asm scan scan.xml --llm
```

Example finding from the bundled sample scan:

```
### [CRITICAL] vsftpd 2.3.4 backdoor -- 10.10.10.5:21/tcp

- Service: vsftpd 2.3.4
- Rule: `CVE-2011-2523` (cve), CVSS 9.8 -- known exploit available
- Score: 100.0/100
- A trojanized build of vsftpd 2.3.4 ... contains a backdoor that opens a
  root shell on TCP/6200 when a username ending in ':)' is supplied.
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2011-2523
```

## How matching works

1. `asm/nmap_parser.py` parses `nmap -oX` output into `Host`/`Port` records
   (address, hostname, protocol, service, product, version).
2. `asm/cve_matcher.py` loads `data/cve_db.json` -- a list of rules, each
   either:
   - `"cve"`: a product + inclusive version range tied to a specific CVE, or
   - `"insecure_protocol"`: a structural weakness (e.g. Telnet is
     cleartext) that applies regardless of version.

   Version strings like `7.2p2` or `2.4.49` are reduced to their leading
   dotted-numeric prefix and compared as tuples, since real-world banners
   rarely follow strict semver.
3. `asm/scoring.py` converts each match into a 0-100 score from its CVSS
   base score, +10 if a known public exploit exists, x0.6 if the match is
   only `unconfirmed`. Hosts are ranked by their single highest-scoring
   finding.
4. `asm/report.py` renders the scored findings as Markdown or JSON.
5. `asm/llm_narrative.py` optionally asks an LLM to turn the structured
   findings into an "Executive Summary / Likely Attack Path / Recommended
   Remediation" narrative -- strictly grounded in the JSON it's given.

## Extending the rule database

`data/cve_db.json` ships with a handful of well-known, illustrative CVEs
(vsftpd 2.3.4 backdoor, EternalBlue, SambaCry, Apache path traversal,
OpenSSH user enumeration, MySQL auth bypass) plus a few insecure-protocol
rules (Telnet, FTP, r-services). It is not a substitute for a real feed
(NVD, Vulners, etc.) -- swap in `--cve-db` with your own database in the
same schema to use it against a real target list.

## Tests

```bash
pytest
```

Covers nmap parsing (including malformed/partial XML), version-range
matching (confirmed vs. unconfirmed vs. no-match), scoring/ranking math,
report rendering, the offline narrator, and the CLI (including error
paths for missing files).

## Disclaimer

For use against systems you own or are explicitly authorized to test.
`examples/sample_scan.xml` is a hand-written, synthetic scan modeled on a
deliberately vulnerable lab environment (e.g. Metasploitable2-style
hosts) -- it is not a real scan of a real system.
