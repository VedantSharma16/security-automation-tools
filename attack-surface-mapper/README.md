# Attack Surface Mapper

A passive external recon tool: point it at a domain and it enumerates DNS
and email-security posture, discovers subdomains via certificate
transparency logs, audits HTTP security headers, and inspects the TLS
certificate — then rolls everything into a single risk-scored report, with
an optional LLM-written analyst narrative on top.

It's the offensive-security counterpart to this repo's other tools
(`log-triage-assistant`, `process_threat_hunter`, `ioc-triage-assistant`),
which are all blue-team detection pipelines. This one answers the
red-team/recon question instead: **what does this domain expose to the
internet, and where is it weak?** — the first step of most real external
penetration tests and bug-bounty recon workflows.

> **Use only against domains you own or are explicitly authorized to test.**
> Every check here is passive or a single benign request (DNS lookups, a
> public certificate-transparency query, one HTTP(S) GET, one TLS
> handshake) — nothing here is an exploit or a scan of internal
> infrastructure — but running recon against a domain without authorization
> can still violate its owner's terms of service or the law. This tool
> includes no safeguard against misuse beyond this notice: authorization is
> the user's responsibility.

## What it checks

| Module | Technique | Example findings |
|---|---|---|
| `dns_recon.py` | Resolves A/AAAA/MX/NS/TXT/CNAME; checks for SPF and DMARC TXT records | Missing SPF/DMARC (email spoofing risk) |
| `subdomain_enum.py` | Queries [crt.sh](https://crt.sh)'s certificate transparency log for every cert ever issued under the domain | Forgotten staging/dev/admin hosts, unusually large attack surface |
| `http_headers.py` | Fetches HTTP and HTTPS, diffs the response headers against a security-header checklist | Missing HSTS/CSP/X-Frame-Options, version-disclosing `Server` banners, HTTP not redirecting to HTTPS |
| `tls_info.py` | Opens a TLS connection, inspects the negotiated protocol and certificate | Expired/soon-to-expire certificates, deprecated TLS 1.0/1.1 |

Findings are combined into a 0–100 risk score (INFO findings are excluded
from scoring — they exist for context, e.g. "6 subdomains discovered") and
rendered as JSON or Markdown.

## Install

```bash
cd attack-surface-mapper
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
asm scan example.com
asm scan example.com --format json --out report.json
asm scan example.com --no-subdomains      # skip the crt.sh query
asm scan example.com --timeout 5          # tighter per-request timeout
asm scan example.com --llm                # use Claude for the narrative
```

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic, offline template summarizer — like the rest of this repo's
tools, it's always usable without any API key, and the *scan* itself never
needs one either way (only the prose narrative is LLM-optional).

A failed subdomain lookup (crt.sh unreachable, rate-limited, etc.) is
logged as a warning and the scan continues with the rest of the checks —
one flaky network dependency shouldn't sink the whole report.

## Architecture

```
asm/
  findings.py         shared Severity enum + Finding dataclass + risk scoring
  dns_recon.py         domain -> DNS records + SPF/DMARC findings
  subdomain_enum.py    domain -> crt.sh subdomain list + exposure findings
  http_headers.py      domain -> HTTP(S) header findings
  tls_info.py          domain -> certificate/protocol findings
  report.py            all of the above -> structured report, JSON/Markdown
  llm_summarizer.py    report dict -> narrative text (Template or Anthropic)
  cli.py               argparse entry point wiring the above together
```

Every network-touching function takes its client as an injectable argument
(`resolver=`, `session=`, `connect_fn=`), so the full pipeline — DNS
resolution, HTTP requests, and raw TLS sockets alike — is unit-testable
without a network connection. `tests/` mocks each one with a small fake and
never makes a real network call.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

45 tests cover DNS record parsing and SPF/DMARC logic, subdomain
dedup/wildcard-filtering, HTTP header analysis (missing headers, banner
disclosure, HTTP→HTTPS redirect checks), TLS certificate/protocol logic
(expiry thresholds, deprecated-protocol detection), report rendering, the
offline LLM fallback, and the CLI end-to-end (including graceful
degradation when subdomain enumeration fails). No network access or API
key is required to run the suite.

## Design notes / limitations

- **Passive by design.** Every check is either a DNS query, a query against
  a third-party public log (crt.sh), or a single request/handshake against
  the target itself — there's no port scanning, brute forcing, or fuzzing.
  That's a deliberate scope: this is a recon/posture tool, not an exploit
  framework.
- **crt.sh is a single source.** Real subdomain enumeration tools (subfinder,
  amass) combine several passive sources; `subdomain_enum.py` is the seam to
  add more.
- **Risk scoring is a heuristic**, not a CVSS-style formal score — it exists
  to triage which findings to look at first, the same as the severity
  scoring in `log-triage-assistant` and `process_threat_hunter`.
