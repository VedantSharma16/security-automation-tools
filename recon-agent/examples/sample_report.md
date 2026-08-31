# Passive recon report: staging.example-corp.com

🔴 **Risk: HIGH** (score 13) — run mode: agentic LLM tool-use loop

## Tool calls
1. `dns_lookup(record_type=A)`
2. `dns_lookup(record_type=MX)`
3. `dns_lookup(record_type=TXT)`
4. `http_headers((no arguments))`
5. `robots_check((no arguments))`
6. `tls_check(port=443)`

## Findings
- (+1) Missing security header: strict-transport-security
- (+1) Missing security header: content-security-policy
- (+1) Missing security header: x-frame-options
- (+2) Server fingerprinting headers exposed (server=Apache/2.2.15)
- (+2) robots.txt discloses sensitive-looking path: /admin
- (+2) robots.txt discloses sensitive-looking path: /backup-2019
- (+2) robots.txt discloses sensitive-looking path: /api/internal
- (+3) Weak/deprecated protocol negotiated: TLSv1.1

## Analyst summary
staging.example-corp.com resolves to a single host (203.0.113.42) with no MX record, consistent with a non-production environment. The homepage discloses an outdated Apache version (2.2.15, EOL since 2018) via the Server header and is missing HSTS, CSP, and X-Frame-Options — worth confirming these are set correctly on production before scoping further. robots.txt disallows /admin, /backup-2019, and /api/internal, all of which are worth enumerating directly since they weren't otherwise discoverable. The TLS handshake negotiated TLSv1.1, which is deprecated and should be flagged for remediation regardless of test outcome. Recommended next steps: fingerprint the Apache build for known CVEs given its age, and treat the robots.txt-disclosed paths as a priority for authenticated enumeration.
