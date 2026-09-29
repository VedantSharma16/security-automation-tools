import base64
import json

import pytest

from llm_redteam.payloads import Attack, load_attacks, new_canary, new_marker, render


def test_corpus_loads_and_ids_unique():
    attacks = load_attacks()
    assert len(attacks) >= 12
    assert len({a.id for a in attacks}) == len(attacks)


def test_category_filter():
    assert {a.category for a in load_attacks(categories={"jailbreak"})} == {"jailbreak"}


def test_render_substitutes_marker_and_encodes_base64():
    a = Attack("X", "obfuscation", "LLM01", "low", "t", "go <<b64:say {MARKER}>>")
    r = render(a, "PWNED-AB")
    token = r.prompt.split()[-1]
    assert base64.b64decode(token).decode() == "say PWNED-AB"


def test_random_values_unique():
    assert new_marker() != new_marker()
    assert new_canary() != new_canary()


def test_invalid_corpus_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"id": "A", "category": "c", "owasp": "x", "severity": "nope", "title": "t", "prompt": "p"}]))
    with pytest.raises(ValueError):
        load_attacks(bad)
