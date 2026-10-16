import pytest

from sigmalite.condition import Condition, ConditionError

NAMES = {"sel_a", "sel_b", "filter"}


def ev(text, hits):
    return Condition(text, NAMES).evaluate(lambda n: n in hits)


def test_precedence_and_over_or():
    assert ev("sel_a or sel_b and filter", {"sel_a"})
    assert not ev("sel_a or sel_b and filter", {"sel_b"})


def test_not_and_parens():
    assert ev("sel_a and not filter", {"sel_a"})
    assert not ev("sel_a and not filter", {"sel_a", "filter"})
    assert ev("(sel_a or sel_b) and not filter", {"sel_b"})


def test_quantifiers():
    assert ev("1 of sel_*", {"sel_b"})
    assert not ev("all of sel_*", {"sel_b"})
    assert ev("all of them", NAMES)


@pytest.mark.parametrize("bad", ["", "sel_a and", "nope", "(sel_a", "sel_a sel_b", "1 of zzz*", "sel_a $"])
def test_invalid_conditions(bad):
    with pytest.raises(ConditionError):
        Condition(bad, NAMES)
