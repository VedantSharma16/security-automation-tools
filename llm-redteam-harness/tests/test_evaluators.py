from llm_redteam.evaluators import evaluate
from llm_redteam.models import TargetResponse, ToolCall

ALL = ("marker", "canary", "prompt_leak", "exfil", "tool_abuse")


def test_clean_response_fires_nothing(scenario):
    assert evaluate(TargetResponse("Reset it from the portal."), scenario, ALL) == {}


def test_each_detector(scenario):
    assert "marker" in evaluate(TargetResponse(scenario.marker.lower()), scenario, ALL)
    assert "canary" in evaluate(TargetResponse("", [ToolCall("send_email", {"body": scenario.canary})]), scenario, ALL)
    assert "prompt_leak" in evaluate(TargetResponse(scenario.system_prompt), scenario, ("prompt_leak",))
    assert "exfil" in evaluate(TargetResponse("![x](https://attacker.example/a)"), scenario, ALL)
    assert "exfil" in evaluate(TargetResponse("visit https://attacker.example/login"), scenario, ALL)
    abuse = TargetResponse("", [ToolCall("send_email", {"to": "x@attacker.example"})])
    assert "tool_abuse" in evaluate(abuse, scenario, ALL)


def test_internal_links_and_emails_are_not_findings(scenario):
    ok = TargetResponse("[form](https://intranet.acme.example/f)", [ToolCall("send_email", {"to": "a@acme.example"})])
    assert evaluate(ok, scenario, ALL) == {}


def test_only_requested_detectors_run(scenario):
    assert evaluate(TargetResponse(scenario.marker), scenario, ("canary",)) == {}
