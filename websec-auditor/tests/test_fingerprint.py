from websec_auditor.fingerprint import fingerprint


def test_server_header_included():
    result = fingerprint([("Server", "nginx/1.18.0")], server_header="nginx/1.18.0")
    assert "Server: nginx/1.18.0" in result


def test_x_powered_by_included():
    result = fingerprint([("X-Powered-By", "PHP/8.1.2")])
    assert "PHP/8.1.2" in result


def test_cookie_signature_detects_php():
    result = fingerprint([("Set-Cookie", "PHPSESSID=abc123; Path=/")])
    assert "PHP" in result


def test_cookie_signature_detects_django():
    result = fingerprint([("Set-Cookie", "csrftoken=xyz; Path=/")])
    assert "Django" in result


def test_body_signature_detects_wordpress():
    result = fingerprint([], body=b'<link href="/wp-content/themes/x/style.css">')
    assert "WordPress" in result


def test_generator_meta_tag_extracted():
    result = fingerprint([], body=b'<meta name="generator" content="WordPress 6.4">')
    assert "WordPress 6.4" in result


def test_no_signatures_returns_empty_list():
    result = fingerprint([("Content-Type", "text/html")])
    assert result == []


def test_results_are_deduplicated_and_sorted():
    result = fingerprint(
        [
            ("Set-Cookie", "PHPSESSID=1"),
            ("Set-Cookie", "PHPSESSID=2"),
        ]
    )
    assert result == ["PHP"]
