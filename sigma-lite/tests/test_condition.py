import pytest

from sigmalite.condition import ConditionError, evaluate, parse, referenced_names

NAMES = {"sel_a": 1, "sel_b": 2, "filter": 3}


def ev(text, true=()):
    return evaluate(parse(text), lambda n: n in true, NAMES)


def test_precedence_and_over_or():
    assert ev("sel_a or sel_b and filter", true={"sel_a"})
    assert not ev("(sel_a or sel_b) and filter", true={"sel_a"})


def test_not():
    assert ev("sel_a and not filter", true={"sel_a"})
    assert not ev("sel_a and not filter", true={"sel_a", "filter"})


def test_quantifiers():
    assert ev("1 of sel*", true={"sel_b"})
    assert not ev("all of sel*", true={"sel_b"})
    assert ev("all of them", true=set(NAMES))
    assert not ev("1 of nomatch*", true=set(NAMES))


def test_referenced_names():
    assert referenced_names(parse("a and (b or not c) and 1 of d*")) == {"a", "b", "c", "d*"}


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "or a", "2 of them", "a )"])
def test_malformed(bad):
    with pytest.raises(ConditionError):
        parse(bad)
