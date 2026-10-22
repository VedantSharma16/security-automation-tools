import pytest

from sigmalite.condition import ConditionError, evaluate, parse_condition


def run(cond, true_names, all_names=("a", "b", "c", "sel_1", "sel_2")):
    return evaluate(parse_condition(cond), list(all_names), lambda n: n in true_names)


def test_and_or_precedence():
    assert run("a or b and c", {"a"})
    assert not run("a or b and c", {"b"})


def test_not_and_parens():
    assert run("not (a or b)", {"c"})
    assert not run("not (a or b)", {"a"})


def test_one_of_glob_and_all_of():
    assert run("1 of sel_*", {"sel_2"})
    assert not run("all of sel_*", {"sel_2"})
    assert run("all of sel_*", {"sel_1", "sel_2"})


def test_them_and_no_glob_match():
    assert run("1 of them", {"c"})
    assert not run("1 of nothing_*", {"a"})


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "and a", "2 of them", "a )"])
def test_malformed(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad)
