from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from .attachments import analyze_attachments, AttachmentInfo
from .content import analyze_content
from .headers import analyze_headers
from .models import Verdict
from .scoring import score
from .urls import analyze_urls, extract_urls


def load_message(path: str | Path) -> Message:
    with open(path, "rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


def _bodies(msg: Message) -> tuple[str, str]:
    text = html = ""
    for part in msg.walk():
        if part.get_filename():
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text += part.get_content()
        elif ctype == "text/html":
            html += part.get_content()
    return text, html


def analyze(msg: Message) -> dict:
    text, html = _bodies(msg)
    subject = str(msg.get("Subject", ""))
    infos, att_findings = analyze_attachments(msg)
    findings = (analyze_headers(msg) + analyze_urls(text, html)
                + att_findings + analyze_content(subject, text or html))
    verdict: Verdict = score(findings)
    return {
        "subject": subject,
        "from": str(msg.get("From", "")),
        "urls": extract_urls(text, html),
        "attachments": [a.__dict__ for a in infos],
        **verdict.to_dict(),
    }
