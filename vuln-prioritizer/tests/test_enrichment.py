from vuln_prioritizer.enrichment import enrich_finding, load_epss_scores, load_kev_catalog
from vuln_prioritizer.ingest import Finding


def _finding(cve_id):
    return Finding(
        host="web01",
        ip="10.0.0.1",
        port=443,
        cve_id=cve_id,
        title="X",
        severity="critical",
        cvss_score=9.0,
        description="",
    )


def test_loads_bundled_kev_catalog():
    catalog = load_kev_catalog()
    assert "CVE-2021-44228" in catalog
    assert catalog["CVE-2021-44228"]["vulnerabilityName"]


def test_loads_bundled_epss_scores():
    scores = load_epss_scores()
    assert scores["CVE-2021-44228"]["epss"] == 0.97


def test_enrich_known_kev_and_epss_cve():
    kev = load_kev_catalog()
    epss = load_epss_scores()
    enrichment = enrich_finding(_finding("CVE-2021-44228"), kev, epss)
    assert enrichment.in_kev is True
    assert enrichment.epss_score == 0.97
    assert enrichment.kev_due_date == "2021-12-24"


def test_enrich_cve_not_in_either_source():
    enrichment = enrich_finding(_finding("CVE-9999-00000"), {}, {})
    assert enrichment.in_kev is False
    assert enrichment.epss_score is None
    assert enrichment.epss_percentile is None


def test_enrich_finding_without_cve_returns_none():
    assert enrich_finding(_finding(None), {}, {}) is None


def test_enrichment_is_case_insensitive():
    kev = {"CVE-2021-44228": {"vulnerabilityName": "Log4Shell"}}
    epss = {"CVE-2021-44228": {"epss": 0.9, "percentile": 0.9}}
    enrichment = enrich_finding(_finding("cve-2021-44228"), kev, epss)
    assert enrichment.in_kev is True
    assert enrichment.cve_id == "CVE-2021-44228"
