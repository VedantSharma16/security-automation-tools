from soc_triage.retriever import TechniqueRetriever


def test_retrieve_ranks_credential_dumping_top_for_mimikatz_query(techniques):
    retriever = TechniqueRetriever(techniques)
    matches = retriever.retrieve("mimikatz.exe sekurlsa::logonpasswords", top_k=3)
    assert matches[0].technique_id == "T1003"
    assert matches[0].score > 0


def test_retrieve_ranks_scanning_top_for_nmap_query(techniques):
    retriever = TechniqueRetriever(techniques)
    matches = retriever.retrieve("nmap -sS -p- full port sweep of subnet", top_k=3)
    assert matches[0].technique_id in {"T1595", "T1046"}


def test_retrieve_respects_top_k(techniques):
    retriever = TechniqueRetriever(techniques)
    matches = retriever.retrieve("powershell encoded command", top_k=2)
    assert len(matches) == 2


def test_retrieve_on_benign_text_has_low_scores(techniques):
    retriever = TechniqueRetriever(techniques)
    matches = retriever.retrieve("notepad.exe opened a local text file", top_k=3)
    assert matches[0].score < 0.3
