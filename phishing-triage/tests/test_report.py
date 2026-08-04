from __future__ import annotations

import json
import os

from phishing_triage.auth_analysis import analyze_authentication
from phishing_triage.content_analysis import analyze_attachments, analyze_content, analyze_sender
from phishing_triage.parser import parse_file
from phishing_triage.report import build_report, render_console, to_json
from phishing_triage.scoring import score_email
from phishing_triage.url_analysis import analyze_links

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISHING_SAMPLE = os.path.join(PROJECT_ROOT, "examples", "phishing_sample.eml")


def _build():
    parsed = parse_file(PHISHING_SAMPLE)
    auth = analyze_authentication(parsed.authentication_results_raw)
    url_findings = analyze_links(parsed.links)
    content = analyze_content(parsed.subject, parsed.visible_text)
    sender = analyze_sender(parsed.from_display, parsed.from_domain)
    attachment_findings = analyze_attachments(parsed.attachments)
    triage = score_email(auth, url_findings, content, sender, attachment_findings)
    return build_report(parsed, auth, url_findings, content, sender, attachment_findings, triage)


def test_build_report_shape():
    report = _build()
    for key in (
        "email", "authentication", "sender", "url_findings",
        "content_findings", "attachment_findings", "triage",
    ):
        assert key in report
    assert report["triage"]["verdict"] == "likely_phishing"
    assert report["email"]["attachment_count"] == 1
    assert report["email"]["link_count"] == 2


def test_to_json_round_trips():
    report = _build()
    payload = json.loads(to_json(report))
    assert payload["triage"]["score"] == report["triage"]["score"]


def test_render_console_contains_verdict_and_reasons_no_color():
    report = _build()
    text = render_console(report, use_color=False)
    assert "\033[" not in text
    assert "LIKELY PHISHING" in text
    assert "Findings:" in text


def test_render_console_uses_color_by_default():
    report = _build()
    text = render_console(report, use_color=True)
    assert "\033[" in text
