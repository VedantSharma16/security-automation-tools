import pytest

from agent.environment import Environment
from agent.tools import TOOL_NAMES, TOOL_SCHEMAS, ToolError, execute_tool


@pytest.fixture
def env() -> Environment:
    return Environment.load()


def test_schemas_cover_dispatch_table() -> None:
    assert TOOL_NAMES == {"search_logs", "lookup_ioc", "get_process_list", "get_process_detail"}
    for schema in TOOL_SCHEMAS:
        assert {"name", "description", "input_schema"} <= schema.keys()


def test_execute_search_logs(env: Environment) -> None:
    result = execute_tool("search_logs", {"host": "web01", "query": "Accepted"}, env)
    assert result["count"] == 1
    assert "Accepted password" in result["matched_lines"][0]


def test_execute_lookup_ioc(env: Environment) -> None:
    result = execute_tool("lookup_ioc", {"indicator": "203.0.113.55"}, env)
    assert result["is_known_malicious"] is True


def test_execute_get_process_list(env: Environment) -> None:
    result = execute_tool("get_process_list", {"host": "db02"}, env)
    assert any(p["name"] == "postgres" for p in result["processes"])


def test_execute_get_process_detail(env: Environment) -> None:
    result = execute_tool("get_process_detail", {"host": "web01", "pid": 4821}, env)
    assert result["found"] is True
    assert result["process"]["sha256"].startswith("a1b2c3")


def test_execute_unknown_tool_raises(env: Environment) -> None:
    with pytest.raises(ToolError):
        execute_tool("delete_everything", {}, env)


def test_execute_unknown_host_raises_tool_error(env: Environment) -> None:
    with pytest.raises(ToolError):
        execute_tool("get_process_list", {"host": "nope"}, env)


def test_execute_missing_argument_raises_tool_error(env: Environment) -> None:
    with pytest.raises(ToolError):
        execute_tool("lookup_ioc", {}, env)
