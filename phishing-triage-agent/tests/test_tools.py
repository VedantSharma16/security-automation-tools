from pathlib import Path

import pytest

from phishing_agent import tools
from phishing_agent.email_parser import parse_eml

FIXTURES = Path(__file__).parent.parent / "examples"


@pytest.fixture
def feeds():
    return tools.DataFeeds.load_default()


@pytest.fixture
def phishing_email():
    return parse_eml((FIXTURES / "phishing_sample.eml").read_bytes())


@pytest.fixture
def benign_email():
    return parse_eml((FIXTURES / "benign_sample.eml").read_bytes())


def test_parse_headers_flags_brand_impersonation(phishing_email, feeds):
    result = tools.parse_headers(phishing_email, feeds)
    assert result["impersonated_brand"] == "PayPal"
    assert result["from_domain"] == "paypa1-secure.com"
    assert result["return_path_mismatches_from"] is True


def test_parse_headers_clean_on_benign(benign_email, feeds):
    result = tools.parse_headers(benign_email, feeds)
    assert result["impersonated_brand"] is None
    assert result["return_path_mismatches_from"] is False


def test_check_authentication_detects_failures(phishing_email, feeds):
    result = tools.check_authentication(phishing_email, feeds)
    assert result["spf"] == "fail"
    assert result["dkim"] == "fail"
    assert result["dmarc"] == "fail"
    assert result["any_fail"] is True
    assert result["all_pass"] is False


def test_check_authentication_all_pass_on_benign(benign_email, feeds):
    result = tools.check_authentication(benign_email, feeds)
    assert result["all_pass"] is True
    assert result["any_fail"] is False


def test_extract_urls(phishing_email, benign_email, feeds):
    assert tools.extract_urls(phishing_email, feeds)["url_count"] == 1
    assert tools.extract_urls(benign_email, feeds)["url_count"] == 0


def test_check_url_reputation_flags_known_malicious_and_typosquat(phishing_email, feeds):
    result = tools.check_url_reputation(phishing_email, feeds)
    assert result["checked"] == 1
    flagged = result["flagged"][0]
    assert "known_malicious" in flagged["flags"]
    assert "typosquat" in flagged["flags"]
    assert flagged["typosquat_target"]["brand"] == "PayPal"


def test_check_url_reputation_clean_on_benign(benign_email, feeds):
    result = tools.check_url_reputation(benign_email, feeds)
    assert result["flagged"] == []


def test_check_attachments_flags_double_extension(phishing_email, feeds):
    result = tools.check_attachments(phishing_email, feeds)
    assert result["attachment_count"] == 1
    flagged = result["flagged"][0]
    assert "double_extension" in flagged["flags"]
    assert "risky_extension" in flagged["flags"]


def test_check_attachments_empty_on_benign(benign_email, feeds):
    result = tools.check_attachments(benign_email, feeds)
    assert result["attachment_count"] == 0
    assert result["flagged"] == []


def test_analyze_language_detects_urgency(phishing_email, benign_email, feeds):
    phishing_result = tools.analyze_language(phishing_email, feeds)
    assert phishing_result["hit_count"] > 0

    benign_result = tools.analyze_language(benign_email, feeds)
    assert benign_result["hit_count"] == 0


def test_tool_registry_and_specs_are_consistent():
    spec_names = {spec["name"] for spec in tools.TOOL_SPECS}
    assert spec_names == set(tools.TOOL_REGISTRY.keys())
    assert set(tools.TOOL_ORDER) == set(tools.TOOL_REGISTRY.keys())
