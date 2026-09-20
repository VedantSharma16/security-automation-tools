from secret_scanner.detectors import RULES, scan_text
from secret_fixtures import (
    fake_aws_access_key_id,
    fake_aws_secret_access_key,
    fake_connection_string,
    fake_generic_high_entropy_secret,
    fake_github_fine_grained_pat,
    fake_github_pat,
    fake_google_api_key,
    fake_jwt,
    fake_npm_token,
    fake_private_key_block,
    fake_slack_token,
    fake_slack_webhook,
    fake_stripe_key,
)

RULE_IDS = {rule.rule_id for rule in RULES}


def _rule_ids_found(text: str) -> set[str]:
    return {match.rule_id for match in scan_text(text)}


def test_all_rules_have_unique_ids():
    ids = [rule.rule_id for rule in RULES]
    assert len(ids) == len(set(ids))


def test_detects_aws_access_key_id():
    assert "aws-access-key-id" in _rule_ids_found(f'key = "{fake_aws_access_key_id()}"')


def test_detects_aws_secret_access_key():
    text = f'aws_secret_key = "{fake_aws_secret_access_key()}"'
    assert "aws-secret-access-key" in _rule_ids_found(text)


def test_detects_github_pat():
    assert "github-pat" in _rule_ids_found(f"token = {fake_github_pat()}")


def test_detects_github_fine_grained_pat():
    assert "github-fine-grained-pat" in _rule_ids_found(f"token = {fake_github_fine_grained_pat()}")


def test_detects_slack_token():
    assert "slack-token" in _rule_ids_found(f"SLACK_TOKEN={fake_slack_token()}")


def test_detects_slack_webhook():
    assert "slack-webhook" in _rule_ids_found(fake_slack_webhook())


def test_detects_google_api_key():
    assert "google-api-key" in _rule_ids_found(f"key = {fake_google_api_key()}")


def test_detects_stripe_key():
    assert "stripe-key" in _rule_ids_found(f"STRIPE_KEY={fake_stripe_key()}")


def test_detects_private_key_block():
    assert "private-key-block" in _rule_ids_found(fake_private_key_block())


def test_detects_jwt():
    assert "jwt" in _rule_ids_found(f"auth = {fake_jwt()}")


def test_detects_generic_connection_string_with_credentials():
    text = f'database_url = "{fake_connection_string()}"'
    assert "generic-connection-string" in _rule_ids_found(text)


def test_detects_npm_token():
    assert "npm-token" in _rule_ids_found(f"//registry.npmjs.org/:_authToken={fake_npm_token()}")


def test_detects_generic_high_entropy_assignment_as_fallback():
    text = f'custom_secret = "{fake_generic_high_entropy_secret()}"'
    assert "generic-high-entropy-assignment" in _rule_ids_found(text)


def test_clean_text_yields_no_matches():
    text = "def add(a, b):\n    return a + b\n\nGREETING = 'hello world'\n"
    assert list(scan_text(text)) == []


def test_placeholder_values_are_not_flagged():
    text = 'api_key = "changeme"\npassword = "your_api_key_here"\n'
    assert list(scan_text(text)) == []


def test_same_match_is_not_double_reported_across_rules():
    # The AWS secret pattern matches the full "key = value" assignment; make sure
    # the identical span isn't also re-emitted by the generic entropy fallback.
    text = f'aws_secret_key = "{fake_aws_secret_access_key()}"'
    matches = list(scan_text(text))
    spans = [(m.start, m.end) for m in matches]
    assert len(spans) == len(set(spans))
