import pytest
from sigmalite.condition import ConditionError, parse_condition

N = {"sel1", "sel2", "filter"}


def ev(text, **r):
    return parse_condition(text, N)({k: r.get(k, False) for k in N})


def test_and_or_not_precedence():
    assert ev("sel1 or sel2 and filter", sel1=True)
    assert not ev("sel1 or sel2 and filter", sel2=True)
    assert ev("sel1 and not filter", sel1=True)
    assert not ev("sel1 and not filter", sel1=True, filter=True)


def test_parentheses():
    assert not ev("(sel1 or sel2) and filter", sel1=True)
    assert ev("(sel1 or sel2) and filter", sel2=True, filter=True)


def test_quantifiers():
    assert ev("1 of sel*", sel2=True)
    assert not ev("all of sel*", sel1=True)
    assert ev("all of them", sel1=True, sel2=True, filter=True)
    assert ev("1 of them and not filter", sel1=True)


@pytest.mark.parametrize("bad", ["", "sel1 and", "(sel1", "nope", "sel1 sel2",
                                 "1 of zzz*", "sel1 )"])
def test_errors(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad, N)
