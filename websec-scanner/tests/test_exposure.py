from __future__ import annotations

from websec.checks.exposure import (
    PROBES,
    evaluate_probe_response,
    parse_robots_disclosures,
)


def test_git_config_probe_matches_on_signature():
    probe = next(p for p in PROBES if p.path == ".git/config")
    finding = evaluate_probe_response(probe, 200, "[core]\n\tfilemode = true\n", "http://x/.git/config")
    assert finding is not None
    assert finding.severity.value == "critical"


def test_probe_ignores_non_200():
    probe = next(p for p in PROBES if p.path == ".git/config")
    assert evaluate_probe_response(probe, 404, "[core]", "http://x/.git/config") is None


def test_probe_requires_content_marker_to_avoid_false_positive():
    probe = next(p for p in PROBES if p.path == ".git/config")
    # A custom 200 "not found" page shouldn't count as an exposed .git/config.
    assert evaluate_probe_response(probe, 200, "<html>404 not found</html>", "http://x/.git/config") is None


def test_probe_without_markers_flags_on_any_200():
    probe = next(p for p in PROBES if p.path == ".env")
    finding = evaluate_probe_response(probe, 200, "SECRET_KEY=whatever", "http://x/.env")
    assert finding is not None


def test_parse_robots_disclosures():
    body = "User-agent: *\nDisallow: /admin\nDisallow: /\nAllow: /public\n"
    paths = parse_robots_disclosures(body)
    assert paths == ["/admin", "/public"]
