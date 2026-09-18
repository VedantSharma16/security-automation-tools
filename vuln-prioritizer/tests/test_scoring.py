from vuln_prioritizer.asset_inventory import Asset
from vuln_prioritizer.enrichment import Enrichment
from vuln_prioritizer.ingest import Finding
from vuln_prioritizer.scoring import build_summary, score_finding, score_findings, tier_for_score


def _finding(cvss=9.0, cve_id="CVE-2021-44228", host="web01"):
    return Finding(
        host=host, ip="10.0.0.1", port=443, cve_id=cve_id, title="X",
        severity="critical", cvss_score=cvss, description="",
    )


def _asset(criticality="medium", internet_facing=False):
    return Asset(hostname="web01", criticality=criticality, internet_facing=internet_facing)


def _enrichment(epss=None, in_kev=False):
    return Enrichment(
        cve_id="CVE-2021-44228", in_kev=in_kev, kev_due_date=None,
        kev_vulnerability_name=None, epss_score=epss, epss_percentile=epss,
    )


def test_tier_boundaries():
    assert tier_for_score(100) == ("P1", "Emergency — remediate immediately")
    assert tier_for_score(85) == ("P1", "Emergency — remediate immediately")
    assert tier_for_score(84.9)[0] == "P2"
    assert tier_for_score(65)[0] == "P2"
    assert tier_for_score(64.9)[0] == "P3"
    assert tier_for_score(40)[0] == "P3"
    assert tier_for_score(0)[0] == "P4"


def test_kev_and_epss_push_score_above_cvss_alone():
    no_enrichment = score_finding(_finding(cvss=6.0), _asset(), None)
    with_enrichment = score_finding(_finding(cvss=6.0), _asset(), _enrichment(epss=0.9, in_kev=True))
    assert with_enrichment.priority_score > no_enrichment.priority_score
    assert any("Known Exploited" in r for r in with_enrichment.rationale)


def test_high_epss_medium_cvss_can_outrank_high_cvss_low_epss():
    # A medium-CVSS finding that's confirmed-exploited (KEV) and highly likely to be
    # exploited again (EPSS) should outrank a higher-CVSS finding with no exploitation signal.
    likely_exploited = score_finding(_finding(cvss=6.5), _asset(), _enrichment(epss=0.95, in_kev=True))
    theoretical_critical = score_finding(_finding(cvss=9.8), _asset(), None)
    assert likely_exploited.priority_score > theoretical_critical.priority_score


def test_asset_criticality_increases_score():
    low = score_finding(_finding(), _asset(criticality="low"), None)
    critical = score_finding(_finding(), _asset(criticality="critical"), None)
    assert critical.priority_score > low.priority_score


def test_internet_facing_increases_score():
    internal = score_finding(_finding(), _asset(internet_facing=False), None)
    external = score_finding(_finding(), _asset(internet_facing=True), None)
    assert external.priority_score > internal.priority_score


def test_score_never_exceeds_100():
    maxed = score_finding(_finding(cvss=10.0), _asset(criticality="critical", internet_facing=True), _enrichment(epss=1.0, in_kev=True))
    assert maxed.priority_score <= 100.0


def test_missing_cvss_scores_as_zero_component_not_error():
    finding = Finding(host="web01", ip=None, port=None, cve_id=None, title="X", severity="info", cvss_score=None, description="")
    scored = score_finding(finding, _asset(), None)
    assert scored.factors["cvss_component"] == 0.0
    assert scored.priority_score >= 0.0


def test_score_findings_sorts_descending():
    low = score_finding(_finding(cvss=2.0), _asset(criticality="low"), None)
    high = score_finding(_finding(cvss=9.5), _asset(criticality="critical", internet_facing=True), _enrichment(epss=0.9, in_kev=True))
    ordered = score_findings([low, high])
    assert ordered[0] is high
    assert ordered[1] is low


def test_build_summary_counts_tiers_and_kev():
    critical = score_finding(_finding(cvss=10.0), _asset(criticality="critical", internet_facing=True), _enrichment(epss=1.0, in_kev=True))
    low = score_finding(_finding(cvss=1.0), _asset(criticality="low"), None)
    summary = build_summary([critical, low])
    assert summary["total_findings"] == 2
    assert summary["kev_findings"] == 1
    assert summary["by_tier"]["P1"] == 1
    assert summary["hosts_affected"] == 1  # same host in both fixtures


def test_build_summary_empty_list():
    summary = build_summary([])
    assert summary["total_findings"] == 0
    assert summary["average_priority_score"] == 0.0
