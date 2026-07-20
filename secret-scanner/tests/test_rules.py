import pytest

from secretscanner.rules import RuleValidationError, load_default_rules, load_rules
from sample_secrets import (
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    DB_CONNECTION_STRING,
    GENERIC_SECRET_VALUE,
    GITHUB_FINE_GRAINED_PAT,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    JWT_TOKEN,
    NPM_ACCESS_TOKEN,
    PRIVATE_KEY_HEADER,
    SLACK_BOT_TOKEN,
    SLACK_WEBHOOK_URL,
    STRIPE_LIVE_SECRET_KEY,
    STRIPE_RESTRICTED_KEY,
    TWILIO_API_KEY,
)

TRUE_POSITIVES = {
    "aws-access-key-id": f'aws_access_key_id = "{AWS_ACCESS_KEY_ID}"',
    "aws-secret-access-key": f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"',
    "github-token": f'token = "{GITHUB_TOKEN}"',
    "github-fine-grained-pat": f'token = "{GITHUB_FINE_GRAINED_PAT}"',
    "slack-token": f'SLACK_TOKEN = "{SLACK_BOT_TOKEN}"',
    "slack-webhook-url": SLACK_WEBHOOK_URL,
    "google-api-key": f'apikey = "{GOOGLE_API_KEY}"',
    "stripe-live-secret-key": f'STRIPE_KEY = "{STRIPE_LIVE_SECRET_KEY}"',
    "stripe-restricted-key": f'STRIPE_KEY = "{STRIPE_RESTRICTED_KEY}"',
    "twilio-api-key": f'TWILIO_KEY = "{TWILIO_API_KEY}"',
    "npm-access-token": f"NPM_TOKEN={NPM_ACCESS_TOKEN}",
    "private-key-block": PRIVATE_KEY_HEADER,
    "jwt-token": f'token = "{JWT_TOKEN}"',
    "hardcoded-db-connection-string": f'DATABASE_URL = "{DB_CONNECTION_STRING}"',
    "generic-secret-assignment": f'client_secret = "{GENERIC_SECRET_VALUE}"',
    "generic-password-assignment": f'password = "{GENERIC_SECRET_VALUE}"',
}


@pytest.fixture(scope="module")
def rules():
    return {r.id: r for r in load_default_rules()}


def test_default_rules_cover_every_true_positive_sample(rules):
    assert set(TRUE_POSITIVES) <= set(rules)


@pytest.mark.parametrize("rule_id,line", TRUE_POSITIVES.items())
def test_rule_matches_its_true_positive_sample(rules, rule_id, line):
    hits = list(rules[rule_id].find_secrets(line))
    assert hits, f"{rule_id} did not match its sample line: {line!r}"


def test_generic_secret_assignment_ignores_placeholder_value(rules):
    line = 'api_key = "your_api_key_here"'
    assert list(rules["generic-secret-assignment"].find_secrets(line)) == []


def test_generic_password_assignment_ignores_short_password(rules):
    line = 'password = "hunter2"'
    assert list(rules["generic-password-assignment"].find_secrets(line)) == []


def test_generic_secret_assignment_ignores_low_entropy_repeated_value(rules):
    line = 'secret_key = "aaaaaaaaaaaaaaaaaaaaaaaa"'
    assert list(rules["generic-secret-assignment"].find_secrets(line)) == []


def test_aws_access_key_rule_does_not_match_unrelated_text(rules):
    line = "this line just talks about an access key without one present"
    assert list(rules["aws-access-key-id"].find_secrets(line)) == []


def test_load_rules_rejects_missing_required_keys():
    raw = "- id: broken\n  pattern: 'x'\n"
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(raw)
        path = fh.name

    with pytest.raises(RuleValidationError):
        load_rules(path)


def test_load_rules_rejects_entropy_check_without_capture_group():
    raw = (
        "- id: broken\n"
        "  pattern: 'no_group_here'\n"
        "  severity: high\n"
        "  category: Test\n"
        "  entropy_check: true\n"
    )
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(raw)
        path = fh.name

    with pytest.raises(RuleValidationError):
        load_rules(path)


def test_load_rules_rejects_duplicate_ids():
    raw = (
        "- id: dup\n  pattern: 'a'\n  severity: low\n  category: Test\n"
        "- id: dup\n  pattern: 'b'\n  severity: low\n  category: Test\n"
    )
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(raw)
        path = fh.name

    with pytest.raises(RuleValidationError):
        load_rules(path)


def test_load_rules_rejects_invalid_severity():
    raw = "- id: bad-severity\n  pattern: 'a'\n  severity: extreme\n  category: Test\n"
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(raw)
        path = fh.name

    with pytest.raises(RuleValidationError):
        load_rules(path)
