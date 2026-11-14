import json

from llm_guardrail.findings import Action
from llm_guardrail.policy import ToolPolicy, ToolSpec

POLICY = ToolPolicy({
    "search": ToolSpec("search"),
    "fetch": ToolSpec("fetch", allowed_domains=("example.com",)),
    "email": ToolSpec("email", side_effects=True, allowed_domains=("example.com",)),
    "diag": ToolSpec("diag", side_effects=True, shell_args=("host",)),
})


def run(name, args, tainted=False, injection_seen=False):
    action, findings = POLICY.evaluate(name, args, tainted=tainted, injection_seen=injection_seen)
    return action, {f.rule_id for f in findings}


def test_unknown_tool_blocked():
    assert run("delete_everything", {}) == (Action.BLOCK, {"tool.not_allowlisted"})


def test_clean_call_allowed():
    assert run("search", {"q": "quarterly report"}) == (Action.ALLOW, set())


def test_url_allowlist_including_subdomains():
    assert run("fetch", {"url": "https://docs.example.com/a"})[0] is Action.ALLOW
    assert run("fetch", {"url": "https://example.com.evil.io/a"}) == (Action.BLOCK, {"tool.url_not_allowlisted"})


def test_nested_args_are_inspected():
    assert run("fetch", {"opts": {"urls": ["https://evil.example"]}})[0] is Action.BLOCK


def test_email_recipient_allowlist():
    assert run("email", {"to": "cfo@example.com"})[0] is Action.ALLOW
    assert run("email", {"to": "x@attacker.example"}) == (Action.BLOCK, {"tool.recipient_not_allowlisted"})


def test_shell_metacharacters_blocked():
    assert run("diag", {"host": "db01"})[0] is Action.ALLOW
    assert run("diag", {"host": "db01 && id"}) == (Action.BLOCK, {"tool.shell_metacharacters"})
    assert run("diag", {"host": "$(whoami)"})[0] is Action.BLOCK


def test_secret_in_arguments_blocked():
    action, ids = run("search", {"q": "AKIAIOSFODNN7EXAMPLE"})
    assert action is Action.BLOCK and ids == {"tool.secret_in_arguments"}


def test_taint_requires_approval_for_side_effects_only():
    assert run("email", {"to": "a@example.com"}, tainted=True) == (
        Action.REQUIRE_APPROVAL, {"tool.side_effect_with_untrusted_context"})
    assert run("search", {"q": "x"}, tainted=True)[0] is Action.ALLOW


def test_injection_in_session_blocks_side_effects():
    action, ids = run("email", {"to": "a@example.com"}, tainted=True, injection_seen=True)
    assert action is Action.BLOCK and ids == {"tool.side_effect_after_injection"}


def test_policy_from_file(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"tools": {"email": {"side_effects": True, "allowed_domains": ["Corp.COM"]}}}))
    policy = ToolPolicy.from_file(path)
    assert policy.tools["email"] == ToolSpec("email", True, ("corp.com",), ())
