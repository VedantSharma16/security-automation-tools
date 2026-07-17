from datetime import datetime, timedelta

from log_triage_agent.models import Event, EventType, IOCs
from log_triage_agent.triage_agent import (
    DeterministicTriageClient,
    TriageAgent,
    TriageClient,
    resolve_default_client,
)

BASE = datetime(2024, 3, 4, 2, 0, 0)


def brute_force_events():
    return [
        Event(
            timestamp=BASE + timedelta(seconds=i * 10),
            host="web01",
            process="sshd",
            event_type=EventType.AUTH_FAILURE,
            raw="synthetic",
            username="root",
            source_ip="203.0.113.7",
        )
        for i in range(5)
    ]


def test_deterministic_client_handles_no_findings():
    client = DeterministicTriageClient()
    summary = client.summarize([], IOCs(), events_analyzed=10)
    assert "10 event" in summary
    assert "No findings" in summary


def test_deterministic_client_mentions_each_finding():
    from log_triage_agent.detectors import run_all_detectors

    events = brute_force_events()
    findings = run_all_detectors(events)
    client = DeterministicTriageClient()

    summary = client.summarize(findings, IOCs(source_ips=["203.0.113.7"]), len(events))

    assert "T1110" in summary
    assert "Block or rate-limit" in summary


def test_triage_agent_uses_injected_client_and_records_source_name():
    class FakeClient(TriageClient):
        source_name = "fake"

        def summarize(self, findings, iocs, events_analyzed):
            return "fake narrative"

    agent = TriageAgent(client=FakeClient())
    report = agent.run(brute_force_events())

    assert report.narrative == "fake narrative"
    assert report.narrative_source == "fake"
    assert report.events_analyzed == 5
    assert len(report.findings) == 1


def test_triage_agent_end_to_end_with_deterministic_client_flags_brute_force():
    agent = TriageAgent(client=DeterministicTriageClient())
    report = agent.run(brute_force_events())

    assert report.highest_severity().value == "high"
    assert report.iocs.source_ips == ["203.0.113.7"]


def test_resolve_default_client_is_deterministic_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = resolve_default_client()
    assert isinstance(client, DeterministicTriageClient)


def test_resolve_default_client_falls_back_when_sdk_missing(monkeypatch):
    # The anthropic SDK isn't installed in this environment; even with a key set,
    # resolve_default_client must degrade gracefully instead of raising.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = resolve_default_client()
    assert isinstance(client, DeterministicTriageClient)
