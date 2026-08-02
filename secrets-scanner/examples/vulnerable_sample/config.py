"""Deliberately vulnerable sample file for demoing Secrets Scanner.

Every value below is a fabricated, non-functional example -- these are not
real credentials for any live account or service. Run the scanner against
this file to see rule-based and entropy-based detection in action:

    secretscan examples/vulnerable_sample/

A couple of formats (Stripe live keys, Slack webhooks) are realistic enough
in shape that committing a literal example trips GitHub's own push
protection -- which is a good sign the signatures in rules/default_rules.yaml
are accurate. Run `python examples/generate_demo_secrets.py` to generate a
local-only, gitignored file demonstrating those rules too.
"""

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # AWS's own public documentation example key
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

DATABASE_URL = "postgres://app_user:Tr0ub4dor3Pass@db.internal.example.com:5432/prod"

# Generic entropy-based detection: no vendor prefix, but the key name and
# randomness are enough to flag it as a likely secret.
internal_service_token = "qN7xZ3mR9pL2vK8wY6bT4cJ1hF5sD0aE"

# Both of these are intentionally NOT flagged, to show the detectors aren't
# just alerting on every string assignment:
API_KEY_PLACEHOLDER = "your-api-key-here"
DEBUG_MODE = "true"
