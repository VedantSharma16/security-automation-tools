from log_sentinel.knowledge_base import KnowledgeBase


def test_retrieve_returns_relevant_entries():
    kb = KnowledgeBase.load()
    results = kb.retrieve("brute force failed password attempts ssh", top_k=2)
    assert results
    assert any(entry["technique_id"] == "T1110" for entry in results)


def test_retrieve_respects_top_k():
    kb = KnowledgeBase.load()
    results = kb.retrieve("password login account root ssh session", top_k=1)
    assert len(results) <= 1


def test_retrieve_returns_empty_for_no_overlap():
    kb = KnowledgeBase([{"technique_id": "T0000", "name": "x", "description": "y", "keywords": ["zzz"]}])
    assert kb.retrieve("completely unrelated query about weather") == []
