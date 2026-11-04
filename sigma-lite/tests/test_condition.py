import pytest
from sigmalite.condition import ConditionError, evaluate, parse_condition

NAMES = ["sel_a", "sel_b", "filter"]


def run(cond, true_set):
    ast = parse_condition(cond, NAMES)
    return evaluate(ast, {n: (lambda n=n: n in true_set) for n in NAMES})


def test_and_or_precedence():
    assert run("sel_a or sel_b and filter", {"sel_a"})
    assert not run("(sel_a or sel_b) and filter", {"sel_a"})


def test_not():
    assert run("sel_a and not filter", {"sel_a"})
    assert not run("sel_a and not filter", {"sel_a", "filter"})


def test_quantifiers():
    assert run("1 of sel_*", {"sel_b"})
    assert not run("all of sel_*", {"sel_b"})
    assert run("all of them", set(NAMES))
    assert run("2 of them", {"sel_a", "filter"})


@pytest.mark.parametrize("bad", ["", "sel_a and", "unknown", "(sel_a", "1 of nomatch*", "sel_a sel_b", "and sel_a"])
def test_invalid(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad, NAMES)


def test_short_circuit_avoids_evaluation():
    called = []
    ast = parse_condition("sel_a or sel_b", NAMES)
    evaluate(ast, {"sel_a": lambda: True, "sel_b": lambda: called.append(1) or True})
    assert not called
