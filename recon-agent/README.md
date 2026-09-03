# recon-agent

An authorized-recon pipeline — DNS/subdomain enumeration, TCP port
scanning, and HTTP/TLS fingerprinting — orchestrated by a genuine Claude
**tool-use loop**: the model decides which recon tool to call next based on
what prior calls turned up, then hands back a short analyst narrative. Every
run also flags concrete risk findings (exposed databases, admin panels,
missing security headers, expiring/unverifiable TLS certs) from the raw
recon data with a deterministic, testable rule set — independent of whether
the LLM is available.

This is the offensive-tooling counterpart to this repo's other,
detection-focused projects (`log-triage-assistant`, `ioc-triage-assistant`,
`process_threat_hunter`), and it demonstrates a different AI-engineering
pattern than those: **agentic tool orchestration** (the model choosing and
sequencing tool calls) rather than retrieval-augmented generation.

## ⚠️ Authorization

Recon and port-scanning tools are dual-use. `recon-agent` refuses to run
against any target that doesn't resolve to a private/loopback address
unless you pass `--i-have-authorization`:

```bash
recon-agent evil-corp.com
# error: 'evil-corp.com' does not resolve to a private/loopback address...

recon-agent evil-corp.com --i-have-authorization   # only if you actually are
```

Loopback (`127.0.0.1`) and RFC1918 private ranges (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`) run without the flag, since those are
almost always the operator's own lab. **Only point this at systems you own
or have explicit written permission to test** (a lab box, a CTF target, or a
signed engagement's defined scope).

## Pipeline

```
target (domain or IP)
        │
        ▼
 authorization.py  ── refuse public targets without --i-have-authorization
        │
        ▼
   agent.py  ──┬── ANTHROPIC_API_KEY set? → Claude tool-use loop:
        │      │      model calls resolve_and_enumerate_subdomains,
        │      │      scan_ports, fingerprint_web_services (via tools.py)
        │      │      in whatever order it decides, then narrates
        │      │
        │      └── no key? → deterministic pipeline: same three tool
        │             functions, called directly in a fixed order
        ▼
 findings.py  ── rule-based risk scoring over the recon data
        │           (exposed services, admin panels, missing security
        │            headers, expiring/unverifiable TLS certs)
        ▼
 report.py  ── console report (colored, severity-sorted) + JSON export
```

## Quickstart

```bash
cd recon-agent
pip install -e ".[dev]"        # add ".[dev,llm]" for the live agentic loop
pytest -q

recon-agent 127.0.0.1                          # scan your own machine, no flag needed
recon-agent 127.0.0.1 --json-out report.json
recon-agent your-lab-domain.internal --i-have-authorization
```

No install needed to just run it:

```bash
PYTHONPATH=. python3 -m recon_agent.cli 127.0.0.1
```

### Enabling the live agentic loop

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
recon-agent 127.0.0.1
```

Without a key, the report's narrative is prefixed
`[offline deterministic pipeline — set ANTHROPIC_API_KEY for an agentic
run]` and is built directly from the structured recon data — not a
placeholder. With a key, Claude is given the three tools in `tools.py` and
decides for itself which to call and when to stop, per the system prompt in
`agent.py`.

## Example output

Run against a local test server that answers on port 8000 with an
`<title>Admin Login</title>` page over plain HTTP:

```
🟠 Overall risk: HIGH
Target: 127.0.0.1  (127.0.0.1)
Tool calls: resolve_and_enumerate_subdomains, scan_ports, fingerprint_web_services

Open ports (1):
  - 8000/tcp (http-alt)

Findings (2):
  [HIGH] sensitive-endpoint @ 127.0.0.1:8000: Page title 'Admin Login' suggests an
  admin/management interface; confirm it requires strong authentication and isn't
  reachable from the open internet.
  [LOW] cleartext-http @ 127.0.0.1:8000: Service responds over plaintext HTTP;
  consider requiring HTTPS.

Analyst narrative:
[offline deterministic pipeline — set ANTHROPIC_API_KEY for an agentic run]
Resolved 127.0.0.1 to 127.0.0.1. Open ports: 8000/http-alt. Fingerprinted 1
web service(s).
```

## Project layout

```
recon-agent/
├── recon_agent/
│   ├── authorization.py    # private/loopback vs. public target guard rail
│   ├── dns_recon.py         # resolve() + threaded enumerate_subdomains()
│   ├── port_scan.py         # threaded TCP connect-scan, curated port list
│   ├── http_fingerprint.py  # headers/title/TLS-expiry, stdlib only
│   ├── findings.py          # raw recon data → severity-ranked risk findings
│   ├── tools.py             # Claude tool-use schemas + dispatcher
│   ├── agent.py             # the tool-use loop + deterministic fallback
│   ├── report.py            # console + JSON report rendering
│   └── cli.py                # argparse CLI
├── wordlists/common_subdomains.txt
└── tests/                    # pytest, offline (injected fakes for
                               # DNS/sockets/HTTP; a fake `anthropic` module
                               # for the agent-loop tests); one suite
                               # exercises the CLI as a subprocess against
                               # a real 127.0.0.1 scan
```

## Design notes / limitations

- **Subdomain wordlist is small and curated**, for a fast demo run. Swap in
  a larger list (e.g. SecLists' `subdomains-top1million-5000.txt`) via
  `--wordlist` for real coverage.
- **Port list is curated, not a full 1-65535 sweep** — it targets the ports
  most relevant to initial-access and misconfiguration findings (databases,
  remote-admin protocols, common web ports). `port_scan.DEFAULT_PORTS` is
  the seam to extend it.
- **TLS certificate inspection uses the system's default trust store**
  (`ssl.create_default_context()`), so a self-signed or otherwise unverifiable
  certificate is reported as a finding (`unverifiable-certificate`) rather
  than silently ignored or crashing the scan.
- **Every network call is dependency-injectable** (`resolver`, `checker`,
  `http_fetcher`, `tls_fetcher` parameters) specifically so the test suite
  never needs real DNS/sockets/TLS beyond the one CLI-subprocess suite that
  deliberately exercises a real loopback scan end-to-end.
- **No subdomain-takeover or CVE-matching logic** — `findings.py` is
  intentionally a small, readable rule set (risky ports, sensitive page
  titles, missing security headers, cert expiry) rather than a general
  vulnerability scanner; it's the seam to extend with more rules.

## Testing

```bash
pytest -q
```

54 tests cover authorization gating, DNS/port/HTTP logic in isolation (via
dependency injection — no real network access needed), the findings rule
set, the tool dispatcher, the full agentic tool-use loop (via a fake
`anthropic` module, including the offline-fallback and max-turns paths),
report rendering, and the CLI end-to-end — including one suite that
actually port-scans and HTTP-fingerprints `127.0.0.1`.
