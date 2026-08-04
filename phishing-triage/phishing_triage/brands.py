"""A small allowlist of commonly-impersonated brands and their legitimate domains.

Used by both `url_analysis` (does a link's host claim to be a brand it isn't?) and
`content_analysis` (does the sender's display name claim to be a brand its address
domain doesn't match?). Intentionally short and illustrative -- see the README for
why this is a heuristic, not a production brand-protection feed.
"""

from __future__ import annotations

# brand keyword (lowercase, as it would appear in a display name or URL) ->
# legitimate domains that keyword is allowed to be associated with.
BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de"),
    "google": ("google.com", "gmail.com", "googlemail.com"),
    "netflix": ("netflix.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "linkedin": ("linkedin.com",),
    "facebook": ("facebook.com", "fb.com"),
    "wells fargo": ("wellsfargo.com",),
    "bank of america": ("bankofamerica.com",),
    "chase": ("chase.com",),
    "irs": ("irs.gov",),
    "usps": ("usps.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "dhl": ("dhl.com",),
    "coinbase": ("coinbase.com",),
    "adobe": ("adobe.com",),
    "dropbox": ("dropbox.com",),
    "zoom": ("zoom.us",),
}


def matching_brand(text: str) -> str | None:
    """Return the first brand keyword found in `text` (case-insensitive), if any."""
    lowered = text.lower()
    for brand in BRAND_DOMAINS:
        if brand in lowered:
            return brand
    return None


def is_legit_domain_for_brand(brand: str, domain: str) -> bool:
    domain = domain.lower()
    return any(
        domain == legit or domain.endswith(f".{legit}")
        for legit in BRAND_DOMAINS.get(brand, ())
    )
