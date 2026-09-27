from secret_scanner.findings import Finding
from secret_scanner.llm_triage import TemplateSummarizer, get_summarizer
from secret_scanner.report import build_report


def _finding(**overrides):
    defaults = dict(
        rule_id="aws-access-key-id",
        category="signature",
        severity="critical",
        file_path="config.py",
        line_number=1,
        redacted_value="AKIA****MNOP",
        description="AWS access key ID",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_template_summarizer_no_findings():
    report = build_report([])
    summary = TemplateSummarizer().summarize(report)
    assert "No secrets detected" in summary


def test_template_summarizer_mentions_rule_and_location():
    report = build_report([_finding()])
    summary = TemplateSummarizer().summarize(report)
    assert "aws-access-key-id" in summary
    assert "config.py:1" in summary


def test_template_summarizer_never_includes_raw_secret_value():
    secret_like = "notARealSecretButShouldNeverAppearRaw123"
    report = build_report([_finding(redacted_value="AKIA****MNOP")])
    summary = TemplateSummarizer().summarize(report)
    assert secret_like not in summary


def test_template_summarizer_warns_about_history_only_findings():
    finding = _finding(source="git_history", commit_hash="abc123", commit_author="Jane",
                        commit_date="2026-01-01", commit_subject="oops")
    report = build_report([], [finding])
    summary = TemplateSummarizer().summarize(report)
    assert "git history" in summary.lower()


def test_get_summarizer_defaults_to_template_when_llm_not_requested():
    assert isinstance(get_summarizer(use_llm=False), TemplateSummarizer)


def test_get_summarizer_falls_back_when_no_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)


def test_get_summarizer_falls_back_when_anthropic_not_installed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test-only")
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("no anthropic package installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)
