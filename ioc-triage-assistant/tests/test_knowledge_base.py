import pytest

from ioc_triage.knowledge_base import TechniqueKnowledgeBase


@pytest.fixture(scope="module")
def kb():
    return TechniqueKnowledgeBase.from_file()


def test_loads_all_bundled_techniques(kb):
    assert len(kb.techniques) >= 10
    ids = {t.id for t in kb.techniques}
    assert "T1059" in ids
    assert "T1486" in ids


def test_query_retrieves_relevant_technique_for_powershell(kb):
    results = kb.query("Attacker executed an encoded PowerShell command to launch malware", top_k=3)
    assert results, "expected at least one match"
    top_ids = {t.id for t, score in results}
    assert "T1059" in top_ids


def test_query_retrieves_ransomware_technique(kb):
    results = kb.query("Files across the file server were encrypted and a ransom note was left", top_k=3)
    top_ids = {t.id for t, score in results}
    assert "T1486" in top_ids


def test_query_respects_top_k(kb):
    results = kb.query("network scanning discovery of open ports across the subnet", top_k=2)
    assert len(results) <= 2


def test_scores_are_sorted_descending(kb):
    results = kb.query("credential dumping mimikatz lsass memory", top_k=5)
    scores = [score for _, score in results]
    assert scores == sorted(scores, reverse=True)


def test_irrelevant_query_yields_low_or_no_scores(kb):
    results = kb.query("the quarterly bake sale raised money for the office party", top_k=3)
    for _, score in results:
        assert score < 0.2
