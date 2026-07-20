"""Synthetic, format-plausible secret values shared across the test suite.

Every value here is entirely fake and generated for this project — none of
it is a real credential. Values are assembled from separate string
fragments rather than written as one contiguous literal so that this file
doesn't itself look like a leaked secret to pattern-based scanners
(including GitHub's own push protection, which matches on file content
regardless of whether the value is actually valid or reachable).
"""


def _join(*parts: str) -> str:
    return "".join(parts)


AWS_ACCESS_KEY_ID = _join("AKIA", "IOSFODNN7", "EXAMPLE")  # AWS's own documented placeholder
AWS_SECRET_ACCESS_KEY = _join("bYLVNGaW8uUCpF9e", "mjxys1fi2xnl", "Q3Fppat3ojd2")
GITHUB_TOKEN = _join("ghp_", "1234567890abcdefghijklmnop", "qrstuvwxyz")
GITHUB_FINE_GRAINED_PAT = _join(
    "github_pat_", "11AABBCCDD0123456789abcdefghijklmnop", "qrstuvwxyzABCDEFGHIJKLMNOP"
)
SLACK_BOT_TOKEN = _join("xoxb-", "123456789012", "-", "123456789012", "-", "abcdefghijklmnopqrstuvwx")
SLACK_WEBHOOK_URL = _join(
    "https://hooks.slack.com/services/", "T00000000/B00000000/", "XXXXXXXXXXXXXXXXXXXXXXXX"
)
GOOGLE_API_KEY = _join("AIza", "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY")
STRIPE_LIVE_SECRET_KEY = _join("sk_live_", "51H8anythingabcdefghijklmnop")
STRIPE_RESTRICTED_KEY = _join("rk_live_", "51H8anythingabcdefghijklmnop")
TWILIO_API_KEY = _join("SK", "1234567890abcdef1234567890abcdef")
NPM_ACCESS_TOKEN = _join("npm_", "1234567890abcdefghijklmnop", "qrstuvwxyz")
JWT_TOKEN = _join(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
)
DB_CONNECTION_STRING = _join(
    "postgres://admin:", "S3cr3tP4ss9xQ", "@db.internal.example.com:5432/prod"
)
GENERIC_SECRET_VALUE = _join("aK9xQ2pL7mZ4", "vR1wT8yU3jH6")
PRIVATE_KEY_HEADER = _join("-----BEGIN ", "RSA PRIVATE KEY", "-----")
