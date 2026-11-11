from phishtriage.checks import Finding
from phishtriage.scoring import score


def f(rule, sev, cat="header"):
    return Finding(rule, cat, sev, "t", "e")


def test_empty_is_clean():
    s = score([])
    assert (s.risk_score, s.verdict, s.highest_severity) == (0, "clean", "info")


def test_single_high_is_suspicious():
    assert score([f("A", "high")]).verdict == "suspicious"


def test_repeats_get_small_capped_bonus():
    assert score([f("A", "high")] * 2).risk_score == 33
    assert score([f("A", "high")] * 20).risk_score == 39


def test_corroboration_bonus_across_categories():
    same = score([f("A", "medium", "url"), f("B", "medium", "url")]).risk_score
    cross = score([f("A", "medium", "url"), f("B", "medium", "header")]).risk_score
    assert cross == same + 10


def test_low_findings_alone_stay_clean():
    s = score([f("A", "low"), f("B", "low", "url")])
    assert s.verdict == "clean" and s.risk_score == 10


def test_capped_at_100_and_malicious():
    s = score([f(str(i), "critical", c) for i, c in enumerate(["url", "header", "attachment"])])
    assert s.risk_score == 100 and s.verdict == "malicious"
    assert s.severity_counts["critical"] == 3
