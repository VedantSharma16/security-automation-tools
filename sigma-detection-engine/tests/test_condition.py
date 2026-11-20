import pytest

from sigma_engine.condition import ConditionError, parse_condition

IDS = ["selection", "selection_a", "selection_b", "filter", "_helper"]


def ev(cond, true_ids):
    return parse_condition(cond, IDS).evaluate(lambda n: n in true_ids)


def test_single_identifier():
    assert ev("selection", {"selection"})
    assert not ev("selection", set())


def test_precedence_and_binds_tighter_than_or():
    # a or (b and c)
    assert ev("selection or selection_a and selection_b", {"selection"})
    assert not ev("selection or selection_a and selection_b", {"selection_a"})


def test_not_and_parentheses():
    cond = "(selection_a or selection_b) and not filter"
    assert ev(cond, {"selection_b"})
    assert not ev(cond, {"selection_b", "filter"})
    assert ev("not not selection", {"selection"})


def test_keywords_case_insensitive():
    assert ev("selection AND NOT filter", {"selection"})


@pytest.mark.parametrize(
    "cond,true_ids,expected",
    [
        ("1 of selection_*", {"selection_b"}, True),
        ("all of selection_*", {"selection_a"}, False),
        ("all of selection_*", {"selection_a", "selection_b"}, True),
        ("any of selection*", {"selection"}, True),
        ("2 of selection*", {"selection", "selection_a"}, True),
        ("2 of selection*", {"selection"}, False),
    ],
)
def test_quantifiers(cond, true_ids, expected):
    assert ev(cond, true_ids) is expected


def test_them_excludes_underscore_identifiers():
    node = parse_condition("all of them", IDS)
    assert "_helper" not in node.identifiers()
    assert ev("all of them", {"selection", "selection_a", "selection_b", "filter"})


def test_condition_list_is_or():
    assert ev(["selection_a", "selection_b"], {"selection_b"})


@pytest.mark.parametrize(
    "cond",
    ["", "selection and", "(selection", "selection)", "unknown", "1 of nomatch*", "0 of them", "selection filter", "and"],
)
def test_invalid_conditions(cond):
    with pytest.raises(ConditionError):
        parse_condition(cond, IDS)


def test_identifiers_reports_all_references():
    node = parse_condition("selection and not (filter or 1 of selection_*)", IDS)
    assert node.identifiers() == {"selection", "filter", "selection_a", "selection_b"}
