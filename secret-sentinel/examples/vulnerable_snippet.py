"""A deliberately vulnerable snippet for trying out Secret Sentinel.

Every value here is fake/invented for demonstration purposes only.
Run: secret-sentinel examples/vulnerable_snippet.py
"""

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
DATABASE_URL = "postgres://appuser:s3cr3tPass@db.internal.example.com:5432/prod"
internal_service_token = "Xk29LpQzT8mNc4Rb"  # no vendor format -- caught by entropy analysis
