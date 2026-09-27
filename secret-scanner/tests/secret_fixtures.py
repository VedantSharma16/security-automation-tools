"""Synthetic, provider-format-matching fake secrets used only by tests.

Every value here is assembled from separate string fragments (joined at
test *run* time) rather than written as one contiguous literal, so no file
in this repository ever contains an unbroken string that looks like a real
credential to naive text scanning. None of these are, or were ever, live
credentials.
"""

from __future__ import annotations

import base64
import os


def random_high_entropy_token(num_bytes: int = 24) -> str:
    """A fresh, non-reproducible random token -- inherently not a real secret."""
    return base64.b64encode(os.urandom(num_bytes)).decode("ascii").rstrip("=")


def low_entropy_token(length: int = 24) -> str:
    return "ab" * (length // 2)


def fake_aws_access_key_id() -> str:
    return "AKIA" + "ABCDEFGHIJKLMNOP"


def fake_aws_secret_access_key() -> str:
    parts = ["wJalrXUtnFEMI", "K7MDENG", "bPxRfiCY", "zQ9mLrTv", "abcd"]
    return "".join(parts)[:40]


def fake_gcp_api_key() -> str:
    # "AIza" + exactly 35 chars, matching AIza[0-9A-Za-z\-_]{35}
    return "AIza" + "SyD" + "abcdefghijklmnopqrstuvwxyz012345"


def fake_github_fine_grained_pat() -> str:
    return "github_pat_" + "11ABCDEFG0" + "abcdefghijklmnopqrstuvwxyz012345"


def fake_github_token() -> str:
    return "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789AB"[:36]


def fake_slack_token() -> str:
    return "xoxb" + "-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"


def fake_slack_webhook() -> str:
    return (
        "https://hooks.slack.com/services/"
        + "T0123456"
        + "/B0123456"
        + "/abcdefghijklmnopqrstuvwx"
    )


def fake_stripe_key() -> str:
    return "sk" + "_live_" + "51H8x2yEXAMPLEnotarealkey12345"


def fake_twilio_key() -> str:
    return "SK" + "0123456789abcdef0123456789abcdef"


def fake_sendgrid_key() -> str:
    return "SG." + "a" * 22 + "." + "b" * 43


def fake_npm_token() -> str:
    return "npm" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789AB"[:36]


def fake_private_key_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----"


def fake_jwt() -> str:
    header = "ey" + "J0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    payload = "ey" + "JzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    return f"{header}.{payload}.{signature}"


def fake_connection_string() -> str:
    return "postgres://" + "dbuser" + ":" + "s3cr3tPassw0rd" + "@" + "db.internal.example.com:5432/prod"


def fake_generic_api_key() -> str:
    return "abcdef0123456789" + "ABCDEF0123456789"


def fake_generic_password() -> str:
    return "correct" + "Horse" + "Battery9"
