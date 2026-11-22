from phishtriage.indicators import Indicator
from phishtriage.scoring import assess, correlate


def ind(id_, severity="medium", category="content"):
    return Indicator(id_, category, severity, id_, "")


def test_empty_is_benign():
    a = assess([])
    assert (a.score, a.verdict, a.highest_severity) == (0, "benign", "info")


def test_score_is_capped_and_sorted():
    a = assess([ind(f"x{n}", "critical") for n in range(5)] + [ind("low", "low")])
    assert a.score == 100 and a.verdict == "malicious"
    assert a.indicators[-1].severity == "low"


def test_single_critical_cannot_be_benign():
    a = assess([ind("attachment_rlo", "critical", "attachment")])
    assert a.score == 45 and a.verdict == "likely-phishing"


def test_single_high_floor_is_suspicious():
    assert assess([ind("url_ip_host", "high", "url")]).verdict == "suspicious"


def test_credential_harvest_correlation():
    out = correlate([ind("content_credential_request"), ind("url_text_mismatch", "high", "url")])
    assert [i.id for i in out] == ["corr_credential_harvest"]


def test_bec_correlation_requires_no_payload():
    base = [ind("content_bec_language"), ind("reply_to_mismatch", "high", "sender")]
    assert "corr_bec" in {i.id for i in correlate(base)}
    with_payload = base + [ind("attachment_executable", "high", "attachment")]
    assert "corr_bec" not in {i.id for i in correlate(with_payload)}


def test_spoofed_sender_correlation():
    out = correlate([ind("display_name_brand_spoof", "high", "sender"),
                     ind("dmarc_fail", "high", "authentication")])
    assert "corr_spoofed_sender" in {i.id for i in out}


def test_unknown_severity_rejected():
    import pytest
    with pytest.raises(ValueError):
        Indicator("x", "content", "severe", "t", "d")
