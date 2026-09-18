from pathlib import Path

from vuln_prioritizer.pipeline import prioritize

FIXTURES = Path(__file__).resolve().parent.parent / "examples"


def test_prioritize_end_to_end_with_assets():
    scored = prioritize(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json")
    assert len(scored) == 8
    # Sorted descending by priority score.
    assert all(scored[i].priority_score >= scored[i + 1].priority_score for i in range(len(scored) - 1))
    # Log4Shell on the internet-facing, critical web01 host should be the top priority.
    top = scored[0]
    assert top.finding.cve_id == "CVE-2021-44228"
    assert top.priority_tier == "P1"
    assert top.asset.internet_facing is True


def test_prioritize_without_assets_uses_medium_default():
    scored = prioritize(FIXTURES / "sample_scan.csv")
    assert all(sf.asset.criticality == "medium" for sf in scored)


def test_prioritize_enriches_kev_findings():
    scored = prioritize(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json")
    kev_findings = [sf for sf in scored if sf.enrichment and sf.enrichment.in_kev]
    assert len(kev_findings) == 5  # the 5 real-world CVEs in the sample scan are all KEV-listed


def test_prioritize_handles_unknown_cve_gracefully():
    scored = prioritize(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json")
    fictional = next(sf for sf in scored if sf.finding.cve_id == "CVE-2023-99999")
    assert fictional.enrichment.in_kev is False
    assert fictional.enrichment.epss_score is None


def test_prioritize_handles_finding_without_cve():
    scored = prioritize(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json")
    no_cve = next(sf for sf in scored if sf.finding.cve_id is None)
    assert no_cve.enrichment is None
