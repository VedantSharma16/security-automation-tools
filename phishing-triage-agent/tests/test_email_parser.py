from pathlib import Path

from phishing_agent.email_parser import parse_eml

FIXTURES = Path(__file__).parent.parent / "examples"


def test_parses_phishing_sample_headers_and_body():
    raw = (FIXTURES / "phishing_sample.eml").read_bytes()
    email = parse_eml(raw)

    assert email.from_display == "PayPal Security"
    assert email.from_addr == "alerts@paypa1-secure.com"
    assert email.to_addrs == ["victim@example-corp.com"]
    assert "Urgent Action Required" in email.subject
    assert email.return_path == "<bounce@mail-relay-9931.ru>"
    assert email.reply_to == "paypal-support@paypa1-secure.com"
    assert email.authentication_results_raw is not None
    assert "spf=fail" in email.authentication_results_raw


def test_extracts_urls_from_body():
    raw = (FIXTURES / "phishing_sample.eml").read_bytes()
    email = parse_eml(raw)
    assert any("paypa1-secure.com/login/verify" in u for u in email.urls)


def test_extracts_attachment_metadata():
    raw = (FIXTURES / "phishing_sample.eml").read_bytes()
    email = parse_eml(raw)
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "account_statement.pdf.exe"
    assert att.size_bytes > 0


def test_parses_benign_sample_with_no_attachments_or_urls():
    raw = (FIXTURES / "benign_sample.eml").read_bytes()
    email = parse_eml(raw)
    assert email.from_addr == "priya.natarajan@example-corp.com"
    assert email.attachments == []
    assert email.urls == []
    assert "spf=pass" in email.authentication_results_raw


def test_to_dict_is_json_serializable():
    import json

    raw = (FIXTURES / "benign_sample.eml").read_bytes()
    email = parse_eml(raw)
    json.dumps(email.to_dict())  # should not raise
