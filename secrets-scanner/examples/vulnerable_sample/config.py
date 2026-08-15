"""Deliberately vulnerable sample config for demoing secretscanner.

Every value below is a clearly-fake, non-functional placeholder (AWS's own
documented example key, and otherwise obvious "FAKE"/all-zero filler) — none
of these are real, live secrets. Scan this file to see secretscanner in
action:

    secretscanner examples/vulnerable_sample --format markdown
"""

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"

STRIPE_SECRET_KEY = "sk_test_FAKEFAKEFAKEFAKE0000notreal"

# Intentionally NOT flagged: low-entropy placeholder text, not a real credential.
DATABASE_PASSWORD = "your_password_here"
