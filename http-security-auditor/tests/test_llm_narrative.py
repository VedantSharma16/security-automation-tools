from http_audit.llm_narrative import LLMNarrator, build_prompt
from http_audit.report import AuditReport, Finding


def _report(findings: list[Finding], score: int = 100, grade: str = "A") -> AuditReport:
    return AuditReport(url="https://example.com/", status_code=200, findings=findings, score=score, grade=grade)


def test_offline_fallback_used_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    narrator = LLMNarrator()
    assert narrator.is_live is False

    report = _report([Finding("headers", "CSP", "high", "missing")], score=80, grade="B")
    summary = narrator.narrate(report)
    assert "offline heuristic summary" in summary
    assert "Grade B" in summary


def test_offline_fallback_reports_no_issues_when_all_pass(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    narrator = LLMNarrator(api_key=None)
    report = _report([Finding("headers", "CSP", "pass", "ok")])
    summary = narrator.narrate(report)
    assert "No actionable issues found" in summary


def test_build_prompt_includes_findings_and_excludes_passes():
    report = _report(
        [
            Finding("headers", "CSP", "high", "missing CSP", "add one"),
            Finding("headers", "nosniff", "pass", "ok"),
        ]
    )
    prompt = build_prompt(report)
    assert "CSP" in prompt
    assert "missing CSP" in prompt
    assert "add one" in prompt
    assert "nosniff" not in prompt


def test_build_prompt_notes_when_everything_passes():
    report = _report([Finding("headers", "CSP", "pass", "ok")])
    prompt = build_prompt(report)
    assert "every check passed" in prompt
