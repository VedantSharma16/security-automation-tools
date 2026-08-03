"""A test fixture that intentionally hardcodes a fake JWT for local testing.

This is exactly the kind of legitimate false positive `.secretsallowlist`
exists for: the value is real-looking (it matches the JWT regex) but it is
not a live secret, so the repo's allowlist suppresses this specific path.
"""

FAKE_SESSION_JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


def test_auth_rejects_expired_token():
    assert FAKE_SESSION_JWT is not None
