# Attack Surface Report — https://demo.example.com

- **Scanned at:** 2026-08-14T09:00:00+00:00
- **Planner mode:** offline
- **HTTP status:** 200
- **Risk score:** 90/100 (critical)
- **Total findings:** 16

## Findings

### [MEDIUM] Missing security header: content-security-policy

- **Category:** headers
- **Detail:** No Content-Security-Policy: the browser has no server-imposed restriction on which scripts/styles/frames may execute, widening the blast radius of any XSS.
- **Recommendation:** Add a content-security-policy response header appropriate to the application.

### [MEDIUM] Missing security header: strict-transport-security

- **Category:** headers
- **Detail:** No HSTS header: browsers will still attempt plain HTTP first, leaving an opening for SSL-stripping / protocol-downgrade attacks on the first visit.
- **Recommendation:** Add a strict-transport-security response header appropriate to the application.

### [MEDIUM] Cookie missing Secure flag

- **Category:** headers
- **Detail:** A Set-Cookie response is missing the Secure flag, so the cookie can be sent over plaintext HTTP.
- **Recommendation:** Add the Secure attribute to all session/auth cookies.

### [MEDIUM] Cookie missing HttpOnly flag

- **Category:** headers
- **Detail:** A Set-Cookie response is missing the HttpOnly flag, so it is readable by JavaScript, raising XSS-to-session-theft impact.
- **Recommendation:** Add the HttpOnly attribute to all session/auth cookies.

### [LOW] Missing security header: x-content-type-options

- **Category:** headers
- **Detail:** No X-Content-Type-Options: nosniff, so browsers may MIME-sniff responses, which has historically enabled content-type confusion attacks.
- **Recommendation:** Add a x-content-type-options response header appropriate to the application.

### [LOW] Missing security header: x-frame-options

- **Category:** headers
- **Detail:** No X-Frame-Options and no frame-ancestors CSP directive: the page can be framed by a third-party site, enabling clickjacking.
- **Recommendation:** Add a x-frame-options response header appropriate to the application.

### [LOW] Server header discloses version information

- **Category:** headers
- **Detail:** Server: 'Apache/2.4.41 (Ubuntu)' — reveals software/version, narrowing exploit selection for an attacker.
- **Recommendation:** Suppress or generalize the Server header at the proxy/web-server config.

### [LOW] X-Powered-By header discloses version information

- **Category:** headers
- **Detail:** X-Powered-By: 'PHP/7.4.3' — reveals software/version, narrowing exploit selection for an attacker.
- **Recommendation:** Suppress or generalize the X-Powered-By header at the proxy/web-server config.

### [LOW] Cookie missing SameSite attribute

- **Category:** headers
- **Detail:** A Set-Cookie response has no SameSite attribute, leaving the default (browser-dependent) cross-site request behavior in place.
- **Recommendation:** Set SameSite=Lax or Strict on session/auth cookies unless cross-site delivery is required.

### [LOW] robots.txt references sensitive-looking paths

- **Category:** robots
- **Detail:** Paths worth manually reviewing: /wp-admin/, /backup/.
- **Recommendation:** robots.txt is not access control — confirm these paths also require authentication.

### [INFO] Missing security header: referrer-policy

- **Category:** headers
- **Detail:** No Referrer-Policy: full URLs (including any sensitive query parameters) may leak to third parties via the Referer header on outbound links.
- **Recommendation:** Add a referrer-policy response header appropriate to the application.

### [INFO] Missing security header: permissions-policy

- **Category:** headers
- **Detail:** No Permissions-Policy: default browser feature access (camera, geolocation, etc.) is left unrestricted for this origin.
- **Recommendation:** Add a permissions-policy response header appropriate to the application.

### [INFO] robots.txt discloses 3 path(s)

- **Category:** robots
- **Detail:** robots.txt lists 3 disallowed/allowed path(s) — a self-disclosed map of areas the site owner doesn't want crawled, often useful recon context.

### [INFO] Detected CMS: WordPress

- **Category:** fingerprint
- **Detail:** Matched via response body. Enumerate the version (readme.html, meta generator) and installed plugins/themes; check both against known CVEs.

### [INFO] Detected web-server: Apache HTTP Server

- **Category:** fingerprint
- **Detail:** Matched via header 'server'. Confirm the version from the Server header and check for known CVEs; consider whether mod_status/server-status is exposed.

### [INFO] Detected language/runtime: PHP

- **Category:** fingerprint
- **Detail:** Matched via header 'x-powered-by'. Note the disclosed PHP version; cross-reference against the PHP end-of-life/CVE list.

## Planner Assessment

[offline deterministic planner — set ANTHROPIC_API_KEY for an agentic run] Ran all available passive checks in fixed order; 16 finding(s) reported.

## Planner Trace

1. `run_header_audit` — offline planner: fixed order, headers first
1. `run_recon_files_scan` — offline planner: fixed order
1. `run_fingerprint` — offline planner: fixed order