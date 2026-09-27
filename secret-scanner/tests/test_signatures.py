import secret_fixtures as fx
from secret_scanner.signatures import SIGNATURES, signature_by_id


def _matches(rule_id: str, line: str) -> bool:
    sig = signature_by_id(rule_id)
    assert sig is not None, f"no signature registered for {rule_id!r}"
    return sig.pattern.search(line) is not None


def test_all_signature_ids_are_unique():
    ids = [s.id for s in SIGNATURES]
    assert len(ids) == len(set(ids))


def test_aws_access_key_id():
    assert _matches("aws-access-key-id", f"key = '{fx.fake_aws_access_key_id()}'")


def test_aws_secret_access_key_requires_context():
    value = fx.fake_aws_secret_access_key()
    assert _matches("aws-secret-access-key", f'aws_secret_access_key = "{value}"')
    # The bare value alone (no aws_secret_access_key= context) should not match this
    # specific high-confidence rule -- that's what keeps it low-noise.
    assert not _matches("aws-secret-access-key", f"random_value = '{value}'")


def test_gcp_api_key():
    assert _matches("gcp-api-key", f"const key = '{fx.fake_gcp_api_key()}';")


def test_github_fine_grained_pat():
    assert _matches("github-fine-grained-pat", fx.fake_github_fine_grained_pat())


def test_github_token():
    assert _matches("github-token", f"export GH_TOKEN={fx.fake_github_token()}")


def test_slack_token():
    assert _matches("slack-token", f'SLACK_TOKEN = "{fx.fake_slack_token()}"')


def test_slack_webhook():
    assert _matches("slack-webhook", fx.fake_slack_webhook())


def test_stripe_live_key():
    assert _matches("stripe-live-key", f'stripe.api_key = "{fx.fake_stripe_key()}"')


def test_twilio_api_key():
    assert _matches("twilio-api-key", fx.fake_twilio_key())


def test_sendgrid_api_key():
    assert _matches("sendgrid-api-key", fx.fake_sendgrid_key())


def test_npm_token():
    assert _matches("npm-token", f"//registry.npmjs.org/:_authToken={fx.fake_npm_token()}")


def test_private_key_block():
    assert _matches("private-key-block", fx.fake_private_key_header())


def test_jwt():
    assert _matches("jwt", f"Authorization: Bearer {fx.fake_jwt()}")


def test_connection_string_with_creds():
    assert _matches("connection-string-with-creds", f'DATABASE_URL = "{fx.fake_connection_string()}"')
    assert not _matches("connection-string-with-creds", "postgres://db.internal.example.com/prod")


def test_generic_api_key_assignment():
    assert _matches("generic-api-key-assignment", f'api_key = "{fx.fake_generic_api_key()}"')


def test_generic_password_assignment():
    assert _matches("generic-password-assignment", f'password = "{fx.fake_generic_password()}"')


def test_generic_password_assignment_ignores_short_values():
    assert not _matches("generic-password-assignment", 'password = "short"')


def test_ordinary_code_does_not_trip_any_signature():
    benign_lines = [
        "def calculate_total(items):",
        "    return sum(item.price for item in items)",
        "# TODO: refactor this into a service class",
        "import os, sys, json",
        "DEBUG = True",
    ]
    for line in benign_lines:
        for sig in SIGNATURES:
            assert not sig.pattern.search(line), f"{sig.id!r} false-matched on {line!r}"
