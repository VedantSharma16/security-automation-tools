from __future__ import annotations

from websec.crawler import extract_get_forms, extract_links, endpoints_with_query_params


def test_extract_links_stays_same_origin():
    html = """
    <a href="/a">a</a>
    <a href="https://other.test/b">b</a>
    <a href="/c#frag">c</a>
    """
    links = extract_links("http://x.test/", html)
    assert links == ["http://x.test/a", "http://x.test/c"]


def test_endpoints_with_query_params_extracts_params():
    endpoints = endpoints_with_query_params(["http://x.test/search?q=hi&page=2", "http://x.test/about"])
    assert len(endpoints) == 1
    assert endpoints[0].params == {"q": "hi", "page": "2"}


def test_extract_get_forms_reads_inputs():
    html = """
    <form method="GET" action="/search">
        <input name="q" value="test">
        <input name="page">
    </form>
    <form method="POST" action="/login">
        <input name="password">
    </form>
    """
    endpoints = extract_get_forms("http://x.test/", html)
    assert len(endpoints) == 1
    assert endpoints[0].url == "http://x.test/search"
    assert endpoints[0].params["q"] == "test"
