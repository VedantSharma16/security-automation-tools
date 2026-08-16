Example console output (`--no-color`) for a fictional target with a mix of
findings, produced by `render_console()` against a `ScanReport`:

```
Web Recon Scanner sends live HTTP/TLS/DNS requests to the target. Only run it against systems you own or are explicitly authorized to test.
Web Recon Report: https://example-shop.test
Scanned at: 2026-08-16T09:00:00+00:00
Risk score: 26  Grade: F

Detected technologies:
  - nginx (web-server) — header Server: nginx/1.18.0
  - PHP (language-runtime) — header X-Powered-By: PHP/7.2.24
  - WordPress (cms) — html match: 'wp-content/themes/shop'
  - jQuery (js-library) — html match: 'jquery.min.js'

TLS: TLSv1.1, subject='example-shop.test', issuer='example-shop.test', expires_in=8 day(s)

Findings (7):
  [CRITICAL] (tls) Weak/deprecated protocol negotiated: TLSv1.1.
  [HIGH    ] (header:Strict-Transport-Security) Missing recommended header 'Strict-Transport-Security'. Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.
  [HIGH    ] (tls) Certificate expires in 8 day(s).
  [MEDIUM  ] (header:Content-Security-Policy) Missing recommended header 'Content-Security-Policy'. Define a restrictive Content-Security-Policy to mitigate XSS/data injection.
  [MEDIUM  ] (tls) Certificate for 'example-shop.test' appears self-signed (subject == issuer).
  [MEDIUM  ] (header:Set-Cookie) Cookie 'PHPSESSID' is missing flag(s): Secure, HttpOnly, SameSite.
  [LOW     ] (header:Server) 'Server: nginx/1.18.0' discloses server/framework details useful for attacker recon.

Resolved subdomains (3):
  - api.example-shop.test -> 203.0.113.10
  - staging.example-shop.test -> 203.0.113.11
  - www.example-shop.test -> 203.0.113.12
```

Note: this is a fabricated target used to demonstrate every check firing at
once. The weak-protocol check (`WEAK_PROTOCOLS` in `webrecon/tls_check.py`)
currently flags `SSLv2`, `SSLv3`, `TLSv1`, and `TLSv1.1`; `TLSv1.2`/`TLSv1.3`
are treated as acceptable. Adjust the set to match your own policy.
