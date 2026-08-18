from codesec.llm_advisor import TemplateAdvisor, get_advisor


def _report(findings):
    by_sev = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for f in findings:
        by_sev[f["severity"]] += 1
    return {
        "summary": {
            "files_scanned": 1,
            "files_skipped": 0,
            "total_findings": len(findings),
            "by_severity": by_sev,
        },
        "findings": findings,
    }


def test_template_advisor_no_findings():
    advisor = TemplateAdvisor()
    narrative = advisor.advise(_report([]))
    assert "No findings" in narrative


def test_template_advisor_lists_priority_fixes():
    findings = [
        {
            "rule_id": "py-sql-injection",
            "title": "Possible SQL Injection",
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "file": "app.py",
            "line": 10,
            "column": 1,
            "snippet": "...",
            "description": "...",
            "remediation": "...",
        }
    ]
    text = TemplateAdvisor().advise(_report(findings))
    assert "py-sql-injection" in text
    assert "app.py:10" in text
    assert "Priority fixes" in text


def test_get_advisor_without_llm_flag_returns_template_advisor():
    advisor = get_advisor(use_llm=False)
    assert isinstance(advisor, TemplateAdvisor)


def test_get_advisor_falls_back_when_api_key_missing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    advisor = get_advisor(use_llm=True)
    assert isinstance(advisor, TemplateAdvisor)
