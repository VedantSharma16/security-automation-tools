import os

# --- Intentionally-fake secrets for secretscan's own demo/tests ---
# These use documentation-standard fake values (e.g. AWS's own published
# "EXAMPLE" test key) or randomly-generated-looking placeholders. None of
# these are live credentials.

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DATABASE_URL = "postgres://admin:SuperSecret1@db.internal.example.com:5432/prod"

# A generic API key with no recognizable provider format -- only caught by
# the entropy heuristic, not a regex rule.
internal_service_token = "9fA2xQ7mZ0pL5vC8rT1yW3nB6hK4eD9gU2i"

password = "correcthorsebatterystaple"


def get_client(key: str = os.environ.get("PROD_API_KEY", AWS_ACCESS_KEY_ID)):
    """Example of the *right* way to do it, shown for contrast: read from env."""
    return key
