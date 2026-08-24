# Web Security Audit: https://pypi.org

Generated: 2026-08-24T09:09:52.270598+00:00

## Summary

- Total findings: 3
- Risk score: 15/100
- Risk rating: MEDIUM
  - INFO: 2
  - MEDIUM: 1

## Findings

### [MEDIUM] TLS certificate expires in 26 day(s)

**OWASP category:** A02:2021 Cryptographic Failures

The certificate is within the renewal warning window.

**Evidence:** `notAfter=Sep 19 23:34:02 2026 GMT`

**Remediation:** Renew the certificate before expiry; consider automated renewal (e.g. ACME/Let's Encrypt).

### [INFO] Informational: /.well-known/security.txt

**OWASP category:** A05:2021 Security Misconfiguration

A security.txt file is present, giving researchers a defined disclosure contact. This is a positive signal, not a vulnerability.

**Evidence:** `GET /.well-known/security.txt -> 200; Contact: mailto:security@pypi.org Expires: 2027-08-23T03:02:25.000Z Preferred-Languages: en Canonical: https://pypi.org/.well-known/security.txt Policy: https:/`

### [INFO] robots.txt discloses potentially sensitive paths

**OWASP category:** A05:2021 Security Misconfiguration

robots.txt lists Disallow entries that look like internal/admin paths. This is not a vulnerability by itself — robots.txt is advisory, not access control — but it's useful reconnaissance for narrowing where else to look.

**Evidence:** `/admin/`

**Remediation:** Enforce access control server-side; don't rely on robots.txt to hide paths.

## Analyst Narrative

[offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis] https://pypi.org: risk rating MEDIUM (15/100, 3 findings). No critical/high findings; remaining issues are lower severity. Recommended next steps: remediate critical/high findings first (credential and TLS exposure before header hardening), then re-run this audit to confirm fixes before considering the target reassessed.
