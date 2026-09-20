"""Fake, format-valid secret values used only by the test suite.

Every value here is split across a string concatenation so that a plain text
scan of *this source file* - including real secret-scanning tools like
GitHub push protection, which would otherwise (correctly!) flag a
contiguous, format-valid AWS/Slack/GitHub credential sitting in a public
repo - never sees the full contiguous string. The concatenation only
happens at runtime, inside the test process, which is where these values
need to exist as plain strings so the detectors under test can actually
match them.
"""

from __future__ import annotations


def fake_aws_access_key_id() -> str:
    return "AKIA" + "ABCDEFGHIJKLMNOP"


def fake_aws_secret_access_key() -> str:
    return "AbCdEfGhIjKlMnOpQrStUvWxYz012345" + "6789ABCD"


def fake_github_pat() -> str:
    return "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz" + "AB"


def fake_github_fine_grained_pat() -> str:
    return "github_pat_" + "11ABCDEFG0123456789012_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"


def fake_slack_token() -> str:
    return "xoxb-" + "1234567890-abcdefghijklmnopqrstuvwx"


def fake_slack_webhook() -> str:
    return "https://hooks.slack.com/services/" + "T00000000/B00000000/abcdefghijklmnopqrstuvwx"


def fake_google_api_key() -> str:
    return "AIza" + "SyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def fake_stripe_key() -> str:
    return "sk_test_" + "1234567890abcdefghijklmnop"


def fake_npm_token() -> str:
    return "npm_" + "a" * 36


def fake_private_key_block() -> str:
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    footer = "-----END " + "RSA PRIVATE KEY-----"
    body = "MIIBOgIBAAJBAKj34" + "GkxFhD90vcNLYLInFEs"
    return f"{header}\n{body}\n{footer}"


def fake_jwt() -> str:
    return "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dQw4w9WgXcQ_abcdefghij"


def fake_connection_string() -> str:
    return "postgres://admin:" + "SuperSecretPassw0rd" + "@db.internal:5432/prod"


def fake_generic_high_entropy_secret() -> str:
    return "Zx9kP2vQeT8mN4wLr7sYh1cB" + "d6fJa3gQ"


def build_dirty_file_text() -> str:
    """A small "source file" containing one instance of each fake secret above,
    used to exercise the full detector set together (mirrors a real leaky file).
    """
    lines = [
        "# Fixture content with intentionally FAKE credentials (format-valid, not",
        "# real), assembled at runtime by tests/secret_fixtures.py.",
        "",
        f'AWS_ACCESS_KEY_ID = "{fake_aws_access_key_id()}"',
        f'aws_secret_key = "{fake_aws_secret_access_key()}"',
        f'GITHUB_TOKEN = "{fake_github_pat()}"',
        f'SLACK_TOKEN = "{fake_slack_token()}"',
        f'STRIPE_KEY = "{fake_stripe_key()}"',
        f'GOOGLE_API_KEY = "{fake_google_api_key()}"',
        f'database_url = "{fake_connection_string()}"',
        f'generic_secret = "{fake_generic_high_entropy_secret()}"',
        "",
        fake_private_key_block(),
        "",
    ]
    return "\n".join(lines)
