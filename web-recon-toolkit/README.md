# webrecon

A command-line reconnaissance pipeline for web applications: it grades
HTTP security headers, inspects the TLS certificate, fingerprints the
technology stack from a local signature database, aggregates everything
into a 0–100 risk score, and can write an LLM-generated analyst narrative
on top — grounded strictly in the structured findings.

> **Authorized testing only.** Point this at assets you own or have
> explicit written permission to test. It never brute-forces, exploits, or
> mutates anything — it only reads the response a single GET request
> already produces.

## What it checks

| Stage | What it does |
|---|---|
| Header grading | Presence/absence of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Permissions-Policy`, `Referrer-Policy`; version-disclosing banners (`Server`, `X-Powered-By`, ...); cookie hardening (`Secure` / `HttpOnly` / `SameSite`). Weighted 0–100 score, A–F grade. |
| TLS inspection | Certificate issuer/subject/expiry, days until expiry (flags ≤30 days as medium, ≤14 as high, expired as critical), obsolete protocol versions. |
| Tech fingerprinting | Matches response headers and body against a local JSON signature database (web servers, CDNs/WAFs, languages, CMSes, JS frameworks) — no external service calls, nothing leaves the machine. |
| Risk scoring | Findings across the above roll up into one 0–100 score and letter grade. |
| Narrative | Optional Claude-written "Executive Summary / Key Risks / Recommended Remediations" section, built only from the JSON findings above — never from raw responses. |

## Two ways to run it

```bash
webrecon scan https://example.com          # live: makes one GET request + a TLS handshake
webrecon analyze captured_response.json    # offline: re-analyze a transaction you already captured
```

`analyze` takes a small JSON fixture (see `examples/`) describing a
previously captured request/response — handy for grading a transaction
exported from Burp/ZAP/your own script without hitting the network again,
and it's what the test suite runs against so CI never needs network access.

## Install

```bash
cd web-recon-toolkit
pip install -e .          # core tool, no LLM dependency
pip install -e ".[llm]"   # + optional Claude-powered narrative
pip install -e ".[dev]"   # + pytest, for running the test suite
```

## Usage

```bash
webrecon scan https://example.com
webrecon scan https://example.com --format json --out report.json
webrecon scan https://example.com --skip-tls          # headers/fingerprint only
webrecon scan https://example.com --llm                # use Claude for the narrative

webrecon analyze examples/wordpress_https_capture.json  # missing headers, verbose banners
webrecon analyze examples/hardened_https_capture.json   # fully hardened baseline
webrecon analyze examples/expiring_cert_capture.json    # cert expiring in <14 days
```

`--llm` requires the `anthropic` package and an `ANTHROPIC_API_KEY`
environment variable. Without either, the tool automatically falls back to
a deterministic, offline template summarizer — the tool is always usable
without any API key or network access.

## Architecture

```
webrecon/
  http_probe.py        URL -> HttpResponse, via an injectable Transport (urllib by default)
  security_headers.py  headers -> weighted 0-100 score, A-F grade, findings
  tls_inspector.py      URL -> TlsInfo, via an injectable CertFetcher (ssl/socket by default)
  fingerprint.py         headers+body -> matched technologies, from data/tech_signatures.json
  pipeline.py             orchestrates the above into one result dict (scan() live, analyze() offline)
  llm_narrative.py         result dict -> narrative text (TemplateSummarizer or AnthropicSummarizer)
  report.py                 result dict -> JSON / Markdown rendering
  cli.py                     argparse entry point wiring the above together
```

The network- and TLS-touching code is isolated behind two small injectable
interfaces (`Transport`, `CertFetcher`), so every scoring/fingerprinting/
reporting rule is unit-tested with canned data — the only code that ever
opens a real socket is `default_transport` and `default_cert_fetcher`,
each covered by its own integration test against a local, throwaway
`http.server` instance (see `conftest.py`). No test in this suite makes an
external network call.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## Why this design

Header grading, TLS expiry, and tech fingerprinting are exactly the kind
of thing that should stay deterministic and rule-based — a pentester or
recruiter reading the JSON output needs to trust it reproduces byte-for-byte
on the same input. The LLM layer is opt-in and additive: it only turns
findings the rules already produced into prose, the same grounding
approach used in `log-triage-assistant/`, so the two projects share a
philosophy even though one is defensive triage and this one is offensive
recon.
