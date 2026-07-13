from ioc_toolkit.defang import defang, refang


def test_defang_ipv4():
    assert defang("1.2.3.4") == "1[.]2[.]3[.]4"


def test_defang_url_scheme():
    assert defang("http://evil.com") == "hxxp://evil[.]com"
    assert defang("https://evil.com/path") == "hxxps://evil[.]com/path"


def test_defang_email():
    assert defang("user@example.com") == "user[at]example[.]com"


def test_refang_reverses_defang():
    original = "Connect to http://evil.com/malware and mail user@example.com from 1.2.3.4"
    assert refang(defang(original)) == original


def test_refang_common_formats():
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert refang("hxxp://bad[.]com") == "http://bad.com"
    assert refang("hxxps://bad[.]com") == "https://bad.com"
    assert refang("user[at]example[.]com") == "user@example.com"
