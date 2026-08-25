"""Parses raw RFC 822 (.eml) messages into a structured, tool-friendly form.

Uses only the Python standard library `email` package — no dependencies —
so parsing is inspectable and testable offline like the rest of the repo's
tools.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
        }


@dataclass
class ParsedEmail:
    from_display: str
    from_addr: str
    to_addrs: list[str]
    subject: str
    date: str
    return_path: str | None
    reply_to: str | None
    authentication_results_raw: str | None
    body_text: str
    urls: list[str] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "from_display": self.from_display,
            "from_addr": self.from_addr,
            "to_addrs": self.to_addrs,
            "subject": self.subject,
            "date": self.date,
            "return_path": self.return_path,
            "reply_to": self.reply_to,
            "authentication_results_raw": self.authentication_results_raw,
            "urls": self.urls,
            "attachments": [a.to_dict() for a in self.attachments],
        }


def _get_body_text(msg) -> str:
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is None:
        return ""
    content = body.get_content()
    if body.get_content_type() == "text/html":
        content = re.sub(r"<[^>]+>", " ", content)
        content = re.sub(r"\s+", " ", content).strip()
    return content


def parse_eml(raw: bytes | str) -> ParsedEmail:
    """Parse raw .eml bytes/text into a :class:`ParsedEmail`."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")

    msg = BytesParser(policy=policy.default).parsebytes(raw)

    display, addr = parseaddr(msg.get("From", ""))
    to_addrs = [a for _, a in getaddresses([msg.get("To", "")]) if a]
    body_text = _get_body_text(msg)
    urls = _URL_RE.findall(body_text)

    attachments = [
        AttachmentInfo(
            filename=part.get_filename() or "(unnamed)",
            content_type=part.get_content_type(),
            size_bytes=len(part.get_payload(decode=True) or b""),
        )
        for part in msg.iter_attachments()
    ]

    return ParsedEmail(
        from_display=display,
        from_addr=addr,
        to_addrs=to_addrs,
        subject=msg.get("Subject", ""),
        date=msg.get("Date", ""),
        return_path=msg.get("Return-Path"),
        reply_to=msg.get("Reply-To"),
        authentication_results_raw=msg.get("Authentication-Results"),
        body_text=body_text,
        urls=urls,
        attachments=attachments,
        raw_headers={k: v for k, v in msg.items()},
    )
