"""Analysis of HTTP response security headers.

Pure function over a plain headers dict, so it needs no network access to
test. Header lookups are case-insensitive per RFC 7230, since raw dicts
(as used in tests and JSON fixtures) don't guarantee that on their own.
"""

from __future__ import annotations

from .models import Finding

MIN_HSTS_MAX_AGE = 15552000  # 180 days, the widely-recommended floor
INFO_LEAK_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


def _get(headers: dict, name: str) -> str | None:
    lname = name.lower()
    for key, value in headers.items():
        if key.lower() == lname:
            return value
    return None


def _parse_directives(value: str) -> dict:
    """Parse a `key=value; key2=value2` style header into a lowercase-keyed dict."""
    out: dict = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
        else:
            out[part.lower()] = True
    return out


def analyze_headers(headers: dict, scheme: str = "https") -> list[Finding]:
    findings: list[Finding] = []

    hsts = _get(headers, "Strict-Transport-Security")
    if scheme == "https":
        if not hsts:
            findings.append(
                Finding(
                    id="header-missing-hsts",
                    category="headers",
                    severity="high",
                    title="Missing Strict-Transport-Security header",
                    description=(
                        "Without HSTS, browsers will happily follow a plain-HTTP "
                        "link or attacker-injected redirect to this host, enabling "
                        "SSL-stripping attacks on the first request."
                    ),
                    remediation=(
                        'Send `Strict-Transport-Security: max-age=31536000; '
                        'includeSubDomains` (and consider preloading).'
                    ),
                )
            )
        else:
            directives = _parse_directives(hsts)
            max_age = int(directives.get("max-age", 0) or 0)
            if max_age < MIN_HSTS_MAX_AGE:
                findings.append(
                    Finding(
                        id="header-weak-hsts-max-age",
                        category="headers",
                        severity="medium",
                        title=f"HSTS max-age is too low ({max_age}s)",
                        description=(
                            "A short max-age shrinks the window during which "
                            "browsers enforce HTTPS-only, weakening protection "
                            "against SSL-stripping."
                        ),
                        remediation="Set max-age to at least 15552000 (180 days), ideally 31536000 (1 year).",
                        evidence=hsts,
                    )
                )
            if "includesubdomains" not in directives:
                findings.append(
                    Finding(
                        id="header-hsts-no-subdomains",
                        category="headers",
                        severity="low",
                        title="HSTS header lacks includeSubDomains",
                        description="Subdomains of this host are not covered by the HSTS policy.",
                        remediation="Add `includeSubDomains` if all subdomains support HTTPS.",
                        evidence=hsts,
                    )
                )

    csp = _get(headers, "Content-Security-Policy")
    if not csp:
        findings.append(
            Finding(
                id="header-missing-csp",
                category="headers",
                severity="medium",
                title="Missing Content-Security-Policy header",
                description=(
                    "Without a CSP, the browser has no defense-in-depth against "
                    "injected scripts if an XSS bug exists elsewhere on the page."
                ),
                remediation="Define a restrictive CSP (start with `default-src 'self'`) and tighten per-resource.",
            )
        )
    else:
        lowered = csp.lower()
        if "unsafe-inline" in lowered:
            findings.append(
                Finding(
                    id="header-csp-unsafe-inline",
                    category="headers",
                    severity="medium",
                    title="CSP allows 'unsafe-inline'",
                    description="`unsafe-inline` largely defeats CSP's protection against injected inline scripts.",
                    remediation="Remove `unsafe-inline`; use nonces/hashes for any inline script that's truly needed.",
                    evidence=csp,
                )
            )
        if "unsafe-eval" in lowered:
            findings.append(
                Finding(
                    id="header-csp-unsafe-eval",
                    category="headers",
                    severity="medium",
                    title="CSP allows 'unsafe-eval'",
                    description="`unsafe-eval` permits `eval()`-style code execution from strings, widening XSS impact.",
                    remediation="Remove `unsafe-eval`; refactor code paths relying on it.",
                    evidence=csp,
                )
            )
        if "default-src *" in lowered or "script-src *" in lowered:
            findings.append(
                Finding(
                    id="header-csp-wildcard-source",
                    category="headers",
                    severity="high",
                    title="CSP uses a wildcard source",
                    description="A `*` source allows script loading from any origin, effectively disabling CSP as a script-injection defense.",
                    remediation="Scope `default-src`/`script-src` to an explicit allowlist of trusted origins.",
                    evidence=csp,
                )
            )

    xcto = _get(headers, "X-Content-Type-Options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append(
            Finding(
                id="header-missing-xcto",
                category="headers",
                severity="low",
                title="Missing or invalid X-Content-Type-Options header",
                description="Without `nosniff`, browsers may MIME-sniff a response into an executable content type.",
                remediation="Send `X-Content-Type-Options: nosniff` on all responses.",
                evidence=xcto or "",
            )
        )

    xfo = _get(headers, "X-Frame-Options")
    csp_has_frame_ancestors = csp is not None and "frame-ancestors" in csp.lower()
    if not xfo and not csp_has_frame_ancestors:
        findings.append(
            Finding(
                id="header-missing-clickjacking-protection",
                category="headers",
                severity="medium",
                title="No clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                description="The page can be embedded in a hidden/opaque iframe on an attacker's site, enabling clickjacking.",
                remediation="Send `Content-Security-Policy: frame-ancestors 'self'` (preferred) or `X-Frame-Options: DENY`/`SAMEORIGIN`.",
            )
        )

    referrer_policy = _get(headers, "Referrer-Policy")
    if not referrer_policy:
        findings.append(
            Finding(
                id="header-missing-referrer-policy",
                category="headers",
                severity="low",
                title="Missing Referrer-Policy header",
                description="Without an explicit policy, full URLs (potentially containing tokens/paths) may leak to third parties via the Referer header.",
                remediation="Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
            )
        )
    elif referrer_policy.lower() in ("unsafe-url",):
        findings.append(
            Finding(
                id="header-unsafe-referrer-policy",
                category="headers",
                severity="low",
                title="Referrer-Policy is set to 'unsafe-url'",
                description="`unsafe-url` leaks the full URL, including any query-string secrets, on every cross-origin navigation.",
                remediation="Use `strict-origin-when-cross-origin` or `no-referrer` instead.",
                evidence=referrer_policy,
            )
        )

    if not _get(headers, "Permissions-Policy"):
        findings.append(
            Finding(
                id="header-missing-permissions-policy",
                category="headers",
                severity="info",
                title="Missing Permissions-Policy header",
                description="Powerful browser features (camera, microphone, geolocation, etc.) are not explicitly restricted.",
                remediation="Send a `Permissions-Policy` header disabling features the site doesn't use.",
            )
        )

    for leak_header in INFO_LEAK_HEADERS:
        value = _get(headers, leak_header)
        if value:
            findings.append(
                Finding(
                    id=f"header-info-disclosure-{leak_header.lower()}",
                    category="headers",
                    severity="info",
                    title=f"{leak_header} header discloses server/framework details",
                    description=(
                        f"`{leak_header}: {value}` helps an attacker fingerprint "
                        "the stack and target version-specific exploits."
                    ),
                    remediation=f"Suppress or genericize the `{leak_header}` header at the web server/proxy layer.",
                    evidence=value,
                )
            )

    return findings
