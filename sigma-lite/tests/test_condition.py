import pytest
from sigmalite.condition import ConditionError, evaluate, parse


def ev(expr, **sel):
    return evaluate(parse(expr), {k: (lambda v=v: v) for k, v in sel.items()})


def test_precedence_and_over_or():
    assert ev("a or b and c", a=True, b=False, c=False)
    assert not ev("(a or b) and c", a=True, b=False, c=False)


def test_not():
    assert ev("a and not b", a=True, b=False)


def test_one_of_wildcard_and_all_of():
    assert ev("1 of sel*", sel1=False, sel2=True, other=False)
    assert not ev("all of sel*", sel1=False, sel2=True)
    assert ev("all of them", x=True, y=True)


def test_short_circuit():
    def boom():
        raise AssertionError("evaluated")
    assert evaluate(parse("a or b"), {"a": lambda: True, "b": boom})


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "not", "1 of", "and a"])
def test_malformed(bad):
    with pytest.raises(ConditionError):
        parse(bad)


def test_unknown_selection():
    with pytest.raises(ConditionError):
        ev("zzz", a=True)
