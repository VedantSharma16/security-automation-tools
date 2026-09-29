import json

from llm_redteam.cli import main
from llm_redteam.payloads import load_attacks
from llm_redteam.report import to_dict, to_markdown
from llm_redteam.runner import gate_failed, resistance_score, run_attacks
from llm_redteam.targets import CallableTarget, HardenedMockTarget, VulnerableMockTarget


def test_vulnerable_target_fails_most_attacks():
    results = run_attacks(VulnerableMockTarget(), load_attacks())
    vuln = [r for r in results if r.verdict == "VULNERABLE"]
    assert len(vuln) >= 10
    assert resistance_score(results) < 30


def test_every_category_breaks_vulnerable_target():
    results = run_attacks(VulnerableMockTarget(), load_attacks())
    assert all(c["vulnerable"] > 0 for c in to_dict(results, "t")["categories"].values())


def test_hardened_target_resists_everything():
    results = run_attacks(HardenedMockTarget(), load_attacks())
    assert all(r.verdict == "RESISTED" for r in results)
    assert resistance_score(results) == 100.0
    assert not gate_failed(results, "low")


def test_target_exception_becomes_error_and_trips_gate():
    def boom(*_):
        raise RuntimeError("timeout")

    results = run_attacks(CallableTarget(boom), load_attacks()[:2])
    assert all(r.verdict == "ERROR" for r in results)
    assert gate_failed(results, "low")


def test_echo_target_leaks_canary():
    results = run_attacks(CallableTarget(lambda sp, u, c: sp), load_attacks(categories={"system_prompt_leak"}))
    assert all(r.verdict == "VULNERABLE" for r in results)


def test_markdown_report_lists_findings():
    results = run_attacks(VulnerableMockTarget(), load_attacks())
    md = to_markdown(results, "mock-vulnerable")
    assert "Resistance score" in md and "PI-001" in md


def test_cli_exit_codes_and_json(tmp_path):
    out = tmp_path / "r.json"
    assert main(["--target", "mock-vulnerable", "--json-out", str(out)]) == 1
    assert json.loads(out.read_text())["vulnerable"] > 0
    assert main(["--target", "mock-hardened"]) == 0
    assert main(["--target", "mock-hardened", "--category", "nonexistent"]) == 2
