import pytest

from llm_redteam.attacks import ATTACKS, CATEGORY_NAMES, filter_attacks, get_attack


def test_attack_ids_are_unique():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))


def test_every_attack_has_a_known_category():
    for attack in ATTACKS:
        assert attack.category in CATEGORY_NAMES
        assert attack.category_name == CATEGORY_NAMES[attack.category]


def test_every_attack_has_nonempty_payload():
    for attack in ATTACKS:
        assert attack.payload.strip()


def test_get_attack_returns_matching_attack():
    attack = get_attack("dan-roleplay")
    assert attack.name == "DAN-style roleplay jailbreak"


def test_get_attack_raises_on_unknown_id():
    with pytest.raises(KeyError):
        get_attack("does-not-exist")


def test_filter_attacks_with_no_categories_returns_all():
    assert filter_attacks(None) == ATTACKS
    assert filter_attacks(()) == ATTACKS


def test_filter_attacks_by_category():
    filtered = filter_attacks(("LLM06",))
    assert filtered
    assert all(a.category == "LLM06" for a in filtered)


def test_filter_attacks_is_case_insensitive():
    assert filter_attacks(("llm08",)) == filter_attacks(("LLM08",))
