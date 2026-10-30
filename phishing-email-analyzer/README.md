# phishscan: Offline Phishing Email Analyzer

Explainable triage for suspicious `.eml` files, built for the first five minutes of a
phishing incident-response ticket. Stdlib-only, no network calls, attachments are
hashed and inspected statically and never executed.

## What it checks

| Layer | Checks |
|---|---|
| Headers | SPF/DKIM/DMARC results from `Authentication-Results`, Reply-To / Return-Path mismatch, display-name spoofing (an email address in the display name that is not the sender) |
| URLs | Raw-IP hosts, shorteners, punycode/IDN homographs, `user@host` tricks, brand lookalikes (including `0/1/3` homoglyph and hyphen padding), abuse-prone TLDs, HTML link text vs. real `href` mismatch |
| Attachments | Executables/scripts, macro-enabled Office files, archives, double extensions (`invoice.pdf.exe`), magic-byte vs. extension mismatch, SHA-256 for threat-intel lookup |
| Content | Urgency, credential, financial and authority lures, with a bonus when themes combine |

Every finding carries a severity, evidence, and (where applicable) a MITRE ATT&CK
technique (T1566.x, T1204.002, T1036.x). Scores are summed with per-finding caps, then
mapped to `clean` / `suspicious` / `likely_phishing`.

## Usage

```bash
pip install -e .[dev]
phishscan tests/fixtures/phish.eml          # human-readable report
phishscan suspicious.eml --json             # machine-readable
```

Exit code is `0` clean, `1` suspicious, `2` likely phishing, `3` error, so it can gate a
mail pipeline or SOAR playbook step.

## Example

```
Verdict : LIKELY_PHISHING (score 100/100)
[HIGH  ] DMARC result: fail [T1566]
[HIGH  ] Display name contains a different email address [T1656]
[HIGH  ] Link text domain differs from actual href [T1566.002]
[HIGH  ] Double extension masquerading as a document [T1036.007]
...
```

## Tests

```bash
pytest
```

## Design notes and limits

- Registrable-domain extraction is a small heuristic, not the Public Suffix List.
- Authentication results are trusted from the receiving MTA's header; verify it was
  added by your own gateway, since senders can forge this header.
- Heuristics trade recall for explainability: every score point traces to a finding.
- Possible extensions: URL detonation/reputation lookups, YARA on attachments, LLM
  narrative summary grounded in the findings (see `log-triage-assistant`).
