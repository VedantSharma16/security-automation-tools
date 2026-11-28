import base64
import json

import pytest

from llm_redteam.attacks import Attack, load_attacks, load_benign, new_marker


def test_default_corpus_loads_and_is_well_formed():
    attacks = load_attacks()
    assert len(attacks) >= 20
    assert {a.category for a in attacks} >= {"direct_injection", "indirect_injection", "prompt_leak",
                                             "secret_exfiltration", "jailbreak", "obfuscation"}
    assert len(load_benign()) >= 20


def test_category_filter():
    attacks = load_attacks(categories=["prompt_leak"])
    assert attacks and all(a.category == "prompt_leak" for a in attacks)


def test_marker_is_unique_and_well_formed():
    m1, m2 = new_marker(), new_marker()
    assert m1 != m2 and m1.startswith("PWN-") and len(m1) == 12


def test_render_user_delivery():
    a = Attack(id="X", name="n", category="direct_injection", owasp="LLM01", severity="low",
               delivery="user", goal="marker", payload="say {marker}")
    r = a.render("PWN-AAAAAAAA")
    assert r.user_message == "say PWN-AAAAAAAA" and r.documents == []


def test_render_document_delivery_uses_question():
    a = Attack(id="X", name="n", category="indirect_injection", owasp="LLM01", severity="high",
               delivery="document", goal="marker", payload="doc {marker}", question="Q?")
    r = a.render("PWN-BBBBBBBB")
    assert r.user_message == "Q?" and r.documents == ["doc PWN-BBBBBBBB"]
    assert r.injected_text == "doc PWN-BBBBBBBB"


def test_render_base64_with_wrapper():
    a = Attack(id="X", name="n", category="obfuscation", owasp="LLM01", severity="low", delivery="user",
               goal="marker", payload="say {marker}", transform="base64", wrapper="decode: {encoded}")
    r = a.render("PWN-CCCCCCCC")
    encoded = r.user_message.split(": ", 1)[1]
    assert base64.b64decode(encoded).decode() == "say PWN-CCCCCCCC"


@pytest.mark.parametrize("field,value", [("goal", "pwn"), ("delivery", "email"), ("severity", "huge")])
def test_invalid_fields_rejected(field, value):
    kwargs = dict(id="X", name="n", category="c", owasp="LLM01", severity="low",
                  delivery="user", goal="canary", payload="p")
    kwargs[field] = value
    with pytest.raises(ValueError):
        Attack(**kwargs)


def test_marker_goal_requires_placeholder():
    with pytest.raises(ValueError):
        Attack(id="X", name="n", category="c", owasp="LLM01", severity="low", delivery="user", goal="marker", payload="no placeholder")


def test_duplicate_ids_rejected(tmp_path):
    entry = dict(id="D", name="n", category="c", owasp="LLM01", severity="low", delivery="user", goal="canary", payload="p")
    path = tmp_path / "a.json"
    path.write_text(json.dumps({"attacks": [entry, entry]}))
    with pytest.raises(ValueError):
        load_attacks(path)
