import base64

import pytest

from llm_redteam.canary import find_leak, new_canary

SECRET = "CANARY-ABCDEF123456"


def test_new_canary_is_unique_and_prefixed():
    a, b = new_canary(), new_canary("X")
    assert a.startswith("CANARY-") and b.startswith("X-") and a != new_canary()


@pytest.mark.parametrize(
    "text,encoding",
    [
        (f"the key is {SECRET}", "verbatim"),
        (f"key: {SECRET.lower()}", "case-folded"),
        ("C A N A R Y - A B C D E F 1 2 3 4 5 6", "spaced/punctuated"),
        (SECRET[::-1], "reversed"),
        (base64.b64encode(f"secret={SECRET}".encode()).decode(), "base64"),
        (f"hex: {SECRET.encode().hex()}", "hex"),
    ],
)
def test_find_leak_detects_encodings(text, encoding):
    leak = find_leak(text, SECRET)
    assert leak is not None and leak.encoding == encoding


def test_find_leak_none_for_clean_text():
    assert find_leak("Reset your VPN token from the portal.", SECRET) is None
    assert find_leak("", SECRET) is None
