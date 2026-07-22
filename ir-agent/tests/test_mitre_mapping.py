from ir_agent.tools.mitre_mapping import map_attack_techniques


def test_maps_brute_force_keywords():
    results = map_attack_techniques("Multiple failed password attempts, classic brute force pattern.")
    ids = [t["id"] for t in results]
    assert "T1110" in ids


def test_scores_multiple_matches_higher():
    results = map_attack_techniques(
        "sudo privilege escalation elevated to root, followed by a crontab cron job for persistence."
    )
    ids = {t["id"] for t in results}
    assert "T1548.003" in ids
    assert "T1053.003" in ids


def test_respects_top_k():
    text = (
        "failed password brute force sudo privilege escalation useradd new user created "
        "crontab cron job phishing credential harvesting"
    )
    results = map_attack_techniques(text, top_k=2)
    assert len(results) <= 2


def test_no_match_returns_empty_list():
    assert map_attack_techniques("Nothing suspicious happened today.") == []
