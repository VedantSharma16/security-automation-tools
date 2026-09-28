"""Parse raw .eml files into a structured Message for the detectors to analyze.

Uses only the standard library `email` package (RFC 5322 / MIME parsing) --
no network access, no third-party dependencies. The parser is deliberately
"dumb": it extracts headers, body text/HTML, and attachment metadata without
judging any of it. All phishing-specific judgment lives in the detectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email import policy
from email.message import Message as EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int


@dataclass
class Message:
    source_file: str
    subject: str
    from_display: str
    from_addr: str
    reply_to_addr: str
    return_path_addr: str
    to_addrs: list[str]
    date: str
    message_id: str
    auth_results_raw: str
    received_count: int
    body_text: str
    body_html: str
    attachments: list[Attachment] = field(default_factory=list)


def _first_addr(raw: str | None) -> tuple[str, str]:
    """Return (display_name, email_addr) for a single-address header, lowercased addr."""
    if not raw:
        return "", ""
    display, addr = parseaddr(raw)
    return display, addr.lower()


def _all_addrs(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [addr.lower() for _, addr in getaddresses([raw]) if addr]


def _extract_body(msg: EmailMessage) -> tuple[str, str]:
    """Walk the MIME tree and return (text_body, html_body), preferring the first part of each type."""
    text_body, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if content_type == "text/plain" and not text_body:
                text_body = content if isinstance(content, str) else ""
            elif content_type == "text/html" and not html_body:
                html_body = content if isinstance(content, str) else ""
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if msg.get_content_type() == "text/html":
            html_body = content if isinstance(content, str) else ""
        else:
            text_body = content if isinstance(content, str) else ""
    return text_body, html_body


def _extract_attachments(msg: EmailMessage) -> list[Attachment]:
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if not filename and disposition != "attachment":
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        attachments.append(
            Attachment(
                filename=filename or "(unnamed)",
                content_type=part.get_content_type(),
                size_bytes=len(payload),
            )
        )
    return attachments


def parse_bytes(raw: bytes, source_file: str = "<memory>") -> Message:
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_display, from_addr = _first_addr(msg.get("From"))
    _, reply_to_addr = _first_addr(msg.get("Reply-To"))
    _, return_path_addr = _first_addr(msg.get("Return-Path"))
    body_text, body_html = _extract_body(msg)

    return Message(
        source_file=source_file,
        subject=str(msg.get("Subject", "")),
        from_display=from_display,
        from_addr=from_addr,
        reply_to_addr=reply_to_addr,
        return_path_addr=return_path_addr,
        to_addrs=_all_addrs(msg.get("To")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        auth_results_raw=str(msg.get("Authentication-Results", "")),
        received_count=len(msg.get_all("Received") or []),
        body_text=body_text,
        body_html=body_html,
        attachments=_extract_attachments(msg),
    )


def parse_file(path: str | Path) -> Message:
    path = Path(path)
    return parse_bytes(path.read_bytes(), source_file=str(path))
