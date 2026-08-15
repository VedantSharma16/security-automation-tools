from secretscanner.patterns import PATTERNS, redact


SAMPLE_LINES = {
    "AWS Access Key ID": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "AWS Secret Access Key (assignment)": "aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    "GitHub Personal Access Token": "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234",
    "Slack Token": "SLACK_BOT_TOKEN=xoxb-FAKEFAKEFAKE-FAKEFAKEFAKE-notarealtoken000000000000",
    # Split across literals so the raw source never contains the contiguous
    # webhook-URL substring (avoids tripping naive secret scanners on this repo).
    "Slack Incoming Webhook URL": "webhook = " + "https://hooks.slack" + ".com/services/FAKE00000FAKE/FAKE00000FAKE/notarealwebhooktoken0000",
    "Stripe Secret Key": "STRIPE_KEY=sk_test_FAKEFAKEFAKEFAKE0000notreal",
    "Google API Key": "apiKey: 'AIzaSyD-1234567890abcdefghijklmnopqrstu'",
    "Twilio API Key": "TWILIO_KEY=SK00000000000000000000000000000000",
    "NPM Access Token": "//registry.npmjs.org/:_authToken=npm_1234567890abcdefghijklmnopqrstuvwxyz",
    "Private Key Block": "-----BEGIN RSA PRIVATE KEY-----",
    "JSON Web Token": (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ),
    "Generic Secret Assignment": "api_key = 'sup3r-s3cr3t-value-1234567890'",
}

BENIGN_LINES = [
    "def calculate_total(items):",
    "# This function connects to the database using a config object.",
    "GITHUB_TOKEN = os.environ['GITHUB_TOKEN']",
    "aws_region = 'us-east-1'",
    "password_field = form.cleaned_data['password']",
]


def _pattern_by_name(name: str):
    return next(p for p in PATTERNS if p.name == name)


def test_every_pattern_has_a_matching_sample():
    assert set(SAMPLE_LINES) == {p.name for p in PATTERNS}


def test_each_pattern_matches_its_sample_line():
    for name, line in SAMPLE_LINES.items():
        pattern = _pattern_by_name(name)
        assert pattern.regex.search(line), f"{name} pattern failed to match its sample"


def test_patterns_do_not_match_benign_lines():
    for line in BENIGN_LINES:
        for pattern in PATTERNS:
            assert not pattern.regex.search(line), (
                f"{pattern.name} incorrectly matched benign line: {line!r}"
            )


def test_redact_keeps_prefix_and_suffix_only():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"


def test_redact_masks_entirely_when_short():
    assert redact("short") == "*****"
