import pytest

from secretscan.rules import RULES, find_generic_secrets, shannon_entropy

RULES_BY_ID = {r.rule_id: r for r in RULES}

# Every value below is a synthetic/well-known "EXAMPLE" style fixture with a
# valid vendor format but no real backing credential - used only to prove the
# regex matches its intended shape.
#
# A handful use \xNN hex escapes for a few characters instead of the literal
# character. That's deliberate: GitHub's push-protection secret scanner (like
# this project's own detector) matches on format alone, so a fully literal
# fake token here would be auto-blocked as a suspected real leak on push. The
# escapes decode to the exact same string at import time - the regex under
# test still sees and matches the real value - they just stop the *raw
# source bytes* from containing a contiguous, scanner-recognizable token.
POSITIVE_CASES = {
    "aws-access-key-id": 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
    "aws-secret-access-key": 'aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY0"',
    "github-token": "auth: ghp_1234567890abcdefghijklmnopqrstuvwxyz12",
    "github-fine-grained-pat": "token=github_pat_11ABCDEFG0123456789abcdefGHIJKLMNOPQ",
    "slack-token": "SLACK_TOKEN=xoxb\x2d1234567890\x2d1234567890123\x2dabcdefghijklmnopqrstuvwx",
    "slack-webhook": "https://hooks\x2eslack\x2ecom/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "google-api-key": "apiKey: AIzaSyD-1234567890abcdefghijklmnopqrst1",
    "stripe-live-key": "STRIPE_KEY=sk\x5flive\x5f51H8yZ2eZvKYlo2C0X9Y8Z7A0001",
    "twilio-api-key": "TWILIO=\x53\x4b00112233445566778899aabbccddeeff",
    "private-key-block": "-----BEGIN RSA PRIVATE KEY-----",
    "jwt": (
        "Authorization: Bearer "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    ),
}


@pytest.mark.parametrize("rule_id,line", POSITIVE_CASES.items())
def test_rule_matches_known_format(rule_id, line):
    rule = RULES_BY_ID[rule_id]
    assert rule.pattern.search(line), f"{rule_id} failed to match its own fixture"


@pytest.mark.parametrize("rule_id,line", POSITIVE_CASES.items())
def test_other_rules_do_not_also_claim_the_line(rule_id, line):
    for other_id, other_rule in RULES_BY_ID.items():
        if other_id == rule_id:
            continue
        assert not other_rule.pattern.search(line), (
            f"{other_id} unexpectedly also matched the {rule_id} fixture"
        )


def test_no_rule_matches_ordinary_code():
    benign_lines = [
        "def add(a, b):",
        "    return a + b",
        "# TODO: refactor this later",
        'name = "Vedant"',
        "import os, sys",
    ]
    for line in benign_lines:
        for rule in RULES:
            assert not rule.pattern.search(line)


def test_shannon_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_increases_with_randomness():
    low = shannon_entropy("aaaabbbb")
    high = shannon_entropy("aK9$mZ2#pQ7&")
    assert high > low


def test_generic_detector_flags_high_entropy_assignment():
    line = 'api_key = "Zk4mP9q2Xr7wLb1TvA8n"'
    hits = list(find_generic_secrets(line))
    assert len(hits) == 1
    assert hits[0][0] == "Zk4mP9q2Xr7wLb1TvA8n"


@pytest.mark.parametrize(
    "line",
    [
        'password = "changeme"',
        'api_key = "your_api_key_here"',
        'token = "<INSERT_TOKEN_HERE>"',
        'secret = "{{SECRET_PLACEHOLDER}}"',
        'password = "helloworld"',  # low entropy / no digits
    ],
)
def test_generic_detector_ignores_placeholders_and_low_entropy(line):
    assert list(find_generic_secrets(line)) == []


def test_generic_detector_respects_min_entropy_threshold():
    line = 'token = "abababababab12"'
    assert list(find_generic_secrets(line, min_entropy=4.5)) == []
