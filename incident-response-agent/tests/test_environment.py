import pytest

from agent.environment import Environment, UnknownHostError


@pytest.fixture
def env() -> Environment:
    return Environment.load()


def test_load_reads_all_fixtures(env: Environment) -> None:
    assert "web01" in env.hosts
    assert "web01" in env.processes
    assert env.log_lines
    assert "203.0.113.55" in env.ioc_feed


def test_search_logs_filters_by_host(env: Environment) -> None:
    lines = env.search_logs("web01")
    assert lines
    assert all("web01" in line for line in lines)
    assert not any("ws-jdoe" in line for line in lines)


def test_search_logs_filters_by_query(env: Environment) -> None:
    lines = env.search_logs("web01", query="Failed password")
    assert lines
    assert all("Failed password" in line for line in lines)


def test_search_logs_unknown_host_raises(env: Environment) -> None:
    with pytest.raises(UnknownHostError):
        env.search_logs("nonexistent-host")


def test_get_process_list(env: Environment) -> None:
    procs = env.get_process_list("web01")
    names = {p["name"] for p in procs}
    assert "kworker/u8:2" in names


def test_get_process_detail_found(env: Environment) -> None:
    proc = env.get_process_detail("web01", 4821)
    assert proc is not None
    assert proc["name"] == "kworker/u8:2"


def test_get_process_detail_missing(env: Environment) -> None:
    assert env.get_process_detail("web01", 999999) is None


def test_lookup_ioc_known_malicious(env: Environment) -> None:
    hit = env.lookup_ioc("203.0.113.55")
    assert hit["is_known_malicious"] is True
    assert hit["confidence"] == "high"


def test_lookup_ioc_unknown_indicator(env: Environment) -> None:
    hit = env.lookup_ioc("8.8.8.8")
    assert hit["is_known_malicious"] is False
