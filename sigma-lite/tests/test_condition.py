import pytest
from sigmalite.condition import ConditionError, parse

N = ["sel_a", "sel_b", "filter"]


def ev(expr, **r):
    return parse(expr, N)({"sel_a": False, "sel_b": False, "filter": False, **r})


def test_precedence_and_not():
    assert ev("sel_a or sel_b and filter", sel_a=True)
    assert not ev("(sel_a or sel_b) and filter", sel_a=True)
    assert ev("sel_a and not filter", sel_a=True)


def test_quantifiers():
    assert ev("1 of sel_*", sel_b=True)
    assert not ev("all of sel_*", sel_b=True)
    assert ev("all of them", sel_a=True, sel_b=True, filter=True)
    assert ev("1 of them and not filter", sel_a=True)


@pytest.mark.parametrize("bad", ["unknown", "sel_a and", "(sel_a", "sel_a sel_b", "1 of nothing*", "2 of them", ")"])
def test_errors(bad):
    with pytest.raises(ConditionError):
        parse(bad, N)
