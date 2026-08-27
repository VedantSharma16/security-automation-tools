from llm_redteam.attacks import ATTACKS, get_attack
from llm_redteam.judge import ResponseJudge
from llm_redteam.scanner import run_attack, run_scan
from llm_redteam.target import DemoHardenedAssistant, DemoVulnerableAssistant


def _offline_judge():
    return ResponseJudge(api_key=None)


def test_full_scan_against_vulnerable_target_flags_every_attack():
    findings = run_scan(DemoVulnerableAssistant(), attacks=ATTACKS, judge=_offline_judge())
    assert len(findings) == len(ATTACKS)
    assert all(f.verdict.vulnerable for f in findings)


def test_full_scan_against_hardened_target_flags_nothing():
    findings = run_scan(DemoHardenedAssistant(), attacks=ATTACKS, judge=_offline_judge())
    assert len(findings) == len(ATTACKS)
    assert not any(f.verdict.vulnerable for f in findings)


def test_indirect_attack_delivers_payload_via_retrieved_context():
    calls = []

    class _RecordingTarget:
        secret_markers = ("RA-7734",)

        def respond(self, user_message, retrieved_context=None):
            calls.append((user_message, retrieved_context))
            return "safe response"

    attack = get_attack("indirect-doc-injection")
    run_attack(_RecordingTarget(), attack, _offline_judge())

    assert len(calls) == 1
    user_message, retrieved_context = calls[0]
    assert attack.payload not in user_message
    assert retrieved_context == attack.payload


def test_direct_attack_delivers_payload_via_user_message():
    calls = []

    class _RecordingTarget:
        secret_markers = ()

        def respond(self, user_message, retrieved_context=None):
            calls.append((user_message, retrieved_context))
            return "safe response"

    attack = get_attack("secret-direct-ask")
    run_attack(_RecordingTarget(), attack, _offline_judge())

    assert calls == [(attack.payload, None)]
