"""Fake configuration file used only to test Secret Sentinel's detectors.

Every value below is a non-functional, invented placeholder — none of these
are real credentials for any live service. The AWS example key pair is the
well-known dummy pair from AWS's own public documentation.
"""

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"

db_password = "correct-horse-battery-staple-99!"

session_token = "Xk29LpQzT8mNc4Rb"

placeholder_api_key = "your-api-key-here"

short_token = "abc123"

DATABASE_URL = "postgres://appuser:s3cr3tPass@db.internal.example.com:5432/prod"

suppressed_secret_key = "Xk29LpQzT8mNc4Rc"  # secret-sentinel:ignore
