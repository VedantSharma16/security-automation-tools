# Deliberately "leaky" sample config for demoing secretscan.
#
# Every value below is either a well-known public placeholder (AWS's own
# documentation example key) or a value invented for this file -- nothing
# here is a real, active credential. A couple of provider-specific examples
# (a live-shaped Stripe/Twilio-style key, a real-looking PEM body) are left
# out of this static file on purpose: GitHub's own push protection flags
# anything matching a known provider *format*, fake or not, so those rules
# are instead exercised by the test suite (see tests/test_cli.py), where the
# fixture is assembled at runtime and never appears as a literal string in
# the repository.
# Run: secretscan examples/

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"          # AWS's own docs placeholder
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI9K7MDENGbPxRfiCYzt7B4wLpqRJ"

GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

DATABASE_URL = "postgres://admin:Sup3rSecretPass!@db.internal:5432/app"

TLS_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAK... (truncated, not a real key)
-----END RSA PRIVATE KEY-----
"""

# These should NOT be flagged -- entropy/placeholder filtering in action:
API_KEY = "changeme"
REQUEST_ID = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"  # looks random, but named like an id
