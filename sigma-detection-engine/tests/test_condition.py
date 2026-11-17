import pytest

from sigmalite.condition import ConditionError, evaluate, parse_condition

SELS = ["sel_a", "sel_b", "filter", "_helper"]


def ev(cond, **vals):
    values = {s: False for s in SELS}
    values.update(vals)
    return evaluate(parse_condition(cond, SELS), values)


def test_single_reference():
    assert ev("sel_a", sel_a=True)
    assert not ev("sel_a")


def test_and_binds_tighter_than_or():
    # sel_a or (sel_b and filter)
    assert ev("sel_a or sel_b and filter", sel_a=True)
    assert not ev("sel_a or sel_b and filter", sel_b=True)


def test_parentheses_override_precedence():
    assert not ev("(sel_a or sel_b) and filter", sel_a=True)
    assert ev("(sel_a or sel_b) and filter", sel_a=True, filter=True)


def test_not_filter_pattern():
    assert ev("sel_a and not filter", sel_a=True)
    assert not ev("sel_a and not filter", sel_a=True, filter=True)


def test_keywords_are_case_insensitive():
    assert ev("sel_a AND NOT filter", sel_a=True)


def test_one_of_wildcard():
    assert ev("1 of sel_*", sel_b=True)
    assert not ev("1 of sel_*", filter=True)


def test_all_of_wildcard():
    assert ev("all of sel_*", sel_a=True, sel_b=True)
    assert not ev("all of sel_*", sel_a=True)


def test_them_excludes_underscore_selections():
    assert ev("all of them", sel_a=True, sel_b=True, filter=True)  # _helper ignored


def test_condition_list_is_ored():
    assert ev(["sel_a", "sel_b"], sel_b=True)


def test_lazy_resolver_short_circuits():
    calls = []

    def resolve(name):
        calls.append(name)
        return False

    evaluate(parse_condition("sel_a and sel_b", SELS), resolve)
    assert calls == ["sel_a"]


@pytest.mark.parametrize("bad", [
    "", "sel_a and", "unknown_sel", "(sel_a", "sel_a sel_b", "1 of nomatch_*",
    "sel_a | count() > 5", "and sel_a",
])
def test_invalid_conditions_raise(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad, SELS)
