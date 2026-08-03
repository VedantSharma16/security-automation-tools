from secretscan.llm_summary import TemplateSummarizer, get_summarizer
from secretscan.report import build_report
from secretscan.scanner import Finding


def _report(findings):
    return build_report(findings, scan_targets={"working_tree": "."})


class TestTemplateSummarizer:
    def test_clean_report_has_no_action_needed(self):
        summary = TemplateSummarizer().summarize(_report([]))
        assert "No hardcoded secrets" in summary

    def test_mentions_git_history_only_findings(self):
        finding = Finding(
            file="config.py",
            line_number=1,
            rule_id="aws-access-key-id",
            severity="critical",
            description="AWS access key ID.",
            redacted_secret="AKIA****EXAM",
            line_preview="aws_key = ...",
            source="git-history",
            commit="abc123",
        )
        summary = TemplateSummarizer().summarize(_report([finding]))
        assert "git history" in summary.lower()
        assert "rotate" in summary.lower()

    def test_mentions_remediation_guidance(self):
        finding = Finding(
            file="config.py",
            line_number=1,
            rule_id="aws-access-key-id",
            severity="critical",
            description="AWS access key ID.",
            redacted_secret="AKIA****EXAM",
            line_preview="aws_key = ...",
        )
        summary = TemplateSummarizer().summarize(_report([finding]))
        assert "rotate" in summary.lower()
        assert "CI" in summary


class TestGetSummarizer:
    def test_use_llm_false_returns_template(self):
        assert isinstance(get_summarizer(False), TemplateSummarizer)

    def test_use_llm_true_without_api_key_falls_back(self, monkeypatch, capsys):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        summarizer = get_summarizer(True)
        assert isinstance(summarizer, TemplateSummarizer)
        assert "falling back" in capsys.readouterr().err
