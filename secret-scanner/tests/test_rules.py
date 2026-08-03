import re

import pytest

from secretscan.rules import DEFAULT_RULES, RULES_BY_ID, SEVERITY_RANK, redact

# Sample values are assembled from fragments at import time rather than
# written as single contiguous literals. Functionally identical for the
# regexes under test, but it keeps this file's raw text from containing a
# byte-for-byte match of a plausible live credential -- which is exactly
# the kind of pattern GitHub's own push-protection secret scanner (and a
# reviewer's eye) would otherwise flag this repo for.
SAMPLES = {
    "aws-access-key-id": 'aws_key = "AKIAIOSFODNN7EXAMPLE"',  # AWS's own published example key
    "aws-secret-access-key": (
        'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY" + '"'
    ),
    "gcp-api-key": "const key = 'AIza" + "SyD1234567890abcdefghijklmnopqrst" + "uv'",
    "gcp-service-account-key": '{"type": "service_account", "project_id": "x"}',
    "github-pat": "token: ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz" + "12",
    "gitlab-pat": "GITLAB_TOKEN=glpat-" + "abcdefghijklmnopqrst",
    "slack-token": "SLACK_TOKEN = 'xoxb-" + "123456789012-123456789012-" + "abcdefghijklmnopqrstuvwx'",
    "slack-webhook": "https://hooks.slack.com/services/T0000000" + "0/B00000000/" + "X" * 24,
    "stripe-key": "sk_live_" + "51H8x" + "X" * 19,
    "sendgrid-key": "SG." + "abcdefghijklmnopqrstuv" + "." + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
    "twilio-key": "SK" + "a" * 32,
    "npm-token": "npm_" + "a" * 36,
    "openai-api-key": "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20,
    "anthropic-api-key": "sk-ant-" + "a" * 30,
    "private-key-block": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "jwt": (
        "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    ),
    "basic-auth-url": "postgres://admin:" + "SuperSecret1" + "@db.internal.example.com:5432/prod",
    "generic-api-key-assignment": 'api_key = "' + "abcdEFGH12345678ijklMNOP" + '"',
    "generic-password-assignment": 'password = "' + "correcthorsebatterystaple" + '"',
}


@pytest.mark.parametrize("rule_id", [r.id for r in DEFAULT_RULES])
def test_rule_matches_its_own_sample(rule_id):
    sample = SAMPLES.get(rule_id)
    assert sample is not None, f"add a sample for rule {rule_id!r}"
    rule = RULES_BY_ID[rule_id]
    assert rule.pattern.search(sample), f"rule {rule_id!r} did not match its sample: {sample!r}"


def test_rule_ids_are_unique():
    ids = [r.id for r in DEFAULT_RULES]
    assert len(ids) == len(set(ids))


def test_all_rules_have_valid_severity():
    for rule in DEFAULT_RULES:
        assert rule.severity in SEVERITY_RANK


def test_benign_code_does_not_match_aws_key():
    benign = "def akia_lookup(x): return x  # not a real key"
    assert not RULES_BY_ID["aws-access-key-id"].pattern.search(benign)


def test_generic_password_rule_ignores_short_values():
    assert not RULES_BY_ID["generic-password-assignment"].pattern.search('password = "abc"')


class TestRedact:
    def test_short_value_fully_masked(self):
        assert redact("abc123", "partial") == "*" * 6

    def test_long_value_keeps_prefix_and_suffix(self):
        result = redact("AKIAIOSFODNN7EXAMPLE", "partial")
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" in result
        assert "OSFODNN7EXA" not in result

    def test_full_mode_always_masks(self):
        result = redact("-----BEGIN RSA PRIVATE KEY-----", "full")
        assert set(result) == {"*"}

    def test_redacted_value_never_contains_original(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        assert secret not in redact(secret, "partial")
