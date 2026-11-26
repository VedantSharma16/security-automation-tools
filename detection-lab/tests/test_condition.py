import pytest

from detlab.condition import parse_condition, evaluate, referenced
from detlab.matcher import RuleSyntaxError

IDS = ["sel_a", "sel_b", "filter_x", "_private"]


def run(cond, truth):
    return evaluate(parse_condition(cond, IDS), lambda name: truth[name])


T = {"sel_a": True, "sel_b": False, "filter_x": False, "_private": True}


@pytest.mark.parametrize(
    "cond,expected",
    [
        ("sel_a", True),
        ("sel_a and sel_b", False),
        ("sel_a or sel_b", True),
        ("sel_a and not filter_x", True),
        ("not sel_a or sel_b", False),
        ("sel_b or sel_a and filter_x", False),  # and binds tighter than or
        ("(sel_b or sel_a) and not filter_x", True),
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("any of sel_*", True),
        ("all of them", False),
        ("1 of them", True),
        ("SEL_A AND NOT filter_x", None),  # keywords are case-insensitive, identifiers are not
    ],
)
def test_condition_semantics(cond, expected):
    if expected is None:
        with pytest.raises(RuleSyntaxError):
            run(cond, T)
        return
    assert run(cond, T) is expected


def test_keywords_case_insensitive():
    assert run("sel_a AND NOT filter_x", T) is True


def test_them_excludes_underscore_selections():
    node = parse_condition("all of them", IDS)
    assert "_private" not in referenced(node)


@pytest.mark.parametrize(
    "cond",
    ["", "sel_a and", "(sel_a", "sel_a sel_b", "missing", "1 of nomatch_*", "sel_a | count() > 5", "and sel_a"],
)
def test_bad_conditions_raise(cond):
    with pytest.raises(RuleSyntaxError):
        parse_condition(cond, IDS)
