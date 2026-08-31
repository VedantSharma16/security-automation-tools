from __future__ import annotations

import json

from recon_agent.agent import ToolCallTrace
from recon_agent.report import to_dict, to_json, to_markdown
from recon_agent.scoring import RiskAssessment, ScoredFinding


def _make_report():
    from recon_agent.agent import ReconReport

    return ReconReport(
        target="example.com",
        is_live=False,
        trace=[ToolCallTrace(tool="dns_lookup", arguments={"record_type": "A"}, result={"ok": True})],
        narrative="Summary text.",
        risk=RiskAssessment(score=4, severity="low", findings=[ScoredFinding(4, "Missing HSTS")]),
    )


def test_to_dict_contains_expected_keys():
    data = to_dict(_make_report())

    assert data["target"] == "example.com"
    assert data["risk"]["severity"] == "low"
    assert data["trace"][0]["tool"] == "dns_lookup"
    assert data["narrative"] == "Summary text."


def test_to_json_round_trips():
    payload = json.loads(to_json(_make_report()))

    assert payload["risk"]["score"] == 4


def test_to_markdown_includes_key_sections():
    md = to_markdown(_make_report())

    assert "# Passive recon report: example.com" in md
    assert "LOW" in md
    assert "dns_lookup(record_type=A)" in md
    assert "Missing HSTS" in md
    assert "Summary text." in md
