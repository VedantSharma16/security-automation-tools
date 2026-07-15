import pytest

from soc_triage.vectorizer import TfidfVectorizer, cosine_similarity, tokenize


def test_tokenize_lowercases_and_drops_stopwords():
    tokens = tokenize("PowerShell -enc SQBFAFgA from the Internet")
    assert "the" not in tokens
    assert "from" not in tokens
    assert "powershell" in tokens
    assert "-enc" in tokens


def test_identical_documents_have_similarity_one():
    vectorizer = TfidfVectorizer().fit(["mimikatz sekurlsa logonpasswords", "nmap port scan"])
    vec_a = vectorizer.transform("mimikatz sekurlsa logonpasswords")
    vec_b = vectorizer.transform("mimikatz sekurlsa logonpasswords")
    assert cosine_similarity(vec_a, vec_b) == pytest.approx(1.0)


def test_unrelated_documents_have_low_similarity():
    vectorizer = TfidfVectorizer().fit(["mimikatz credential dumping", "nmap network port scan"])
    vec_a = vectorizer.transform("mimikatz credential dumping")
    vec_b = vectorizer.transform("nmap network port scan")
    assert cosine_similarity(vec_a, vec_b) < 0.2


def test_empty_vector_similarity_is_zero():
    vectorizer = TfidfVectorizer().fit(["some document"])
    empty_vec = vectorizer.transform("")
    other_vec = vectorizer.transform("some document")
    assert cosine_similarity(empty_vec, other_vec) == 0.0


def test_transform_before_fit_raises():
    vectorizer = TfidfVectorizer()
    try:
        vectorizer.transform("test")
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass
