from asm.cve_matcher import Match, VulnRule
from asm.scoring import rank_hosts, score_match, score_matches, severity_for_score


def make_match(**overrides) -> Match:
    rule = VulnRule(
        rule_id="TEST-1",
        rule_type="cve",
        product_aliases=["openssh"],
        title="Test rule",
        description="desc",
        cvss=overrides.pop("cvss", 7.5),
        severity="high",
        exploit_available=overrides.pop("exploit_available", False),
        reference="https://example.invalid",
        version_min="7.0",
        version_max="7.5",
    )
    defaults = dict(
        host="10.0.0.1",
        hostname="",
        port_id=22,
        protocol="tcp",
        service_label="OpenSSH 7.2p2",
        rule=rule,
        confidence=overrides.pop("confidence", "confirmed"),
    )
    defaults.update(overrides)
    return Match(**defaults)


def test_score_match_scales_cvss_to_100():
    m = make_match(cvss=5.0)
    assert score_match(m) == 50.0


def test_score_match_adds_exploit_bonus():
    m = make_match(cvss=5.0, exploit_available=True)
    assert score_match(m) == 60.0


def test_score_match_caps_at_100():
    m = make_match(cvss=9.8, exploit_available=True)
    assert score_match(m) == 100.0


def test_score_match_penalizes_unconfirmed_matches():
    confirmed = score_match(make_match(cvss=8.0, confidence="confirmed"))
    unconfirmed = score_match(make_match(cvss=8.0, confidence="unconfirmed"))
    assert unconfirmed < confirmed


def test_severity_thresholds():
    assert severity_for_score(95) == "critical"
    assert severity_for_score(75) == "high"
    assert severity_for_score(45) == "medium"
    assert severity_for_score(10) == "low"
    assert severity_for_score(0) == "info"


def test_score_matches_sorts_descending():
    low = make_match(cvss=2.0)
    high = make_match(cvss=9.0)
    scored = score_matches([low, high])
    assert scored[0].match is high
    assert scored[0].score >= scored[1].score


def test_rank_hosts_groups_by_host_and_takes_max():
    m1 = make_match(host="10.0.0.1", cvss=3.0)
    m2 = make_match(host="10.0.0.1", cvss=9.0)
    m3 = make_match(host="10.0.0.2", cvss=5.0)
    scored = score_matches([m1, m2, m3])
    risks = rank_hosts(scored)

    assert len(risks) == 2
    top = risks[0]
    assert top.host == "10.0.0.1"
    assert top.finding_count == 2
    assert top.score == score_match(m2)
