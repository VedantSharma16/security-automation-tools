"""Parse a raw .eml file into a structured ParsedEmail — headers, auth-chain
metadata, body text/HTML, extracted links, and attachment metadata (with
sha256 hashes, never executed or opened).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from .htmlutils import Link, extract_links, html_to_text


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str
    date_raw: str | None
    message_id: str | None
    from_display_name: str
    from_addr: str
    from_domain: str
    reply_to_addr: str | None
    reply_to_domain: str | None
    return_path_addr: str | None
    return_path_domain: str | None
    received_headers: list[str] = field(default_factory=list)
    auth_results_headers: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    html_links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    raw_headers: dict[str, list[str]] = field(default_factory=dict)

    @property
    def display_name_lower(self) -> str:
        return self.from_display_name.lower()


def _domain_of(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.rsplit("@", 1)[-1].strip().lower() or None


def _first_addr(msg: Message, header: str) -> tuple[str, str]:
    """Return (display_name, address) for the first address in a header."""
    raw = msg.get(header)
    if not raw:
        return "", ""
    parsed = getaddresses([raw])
    if not parsed:
        return "", ""
    name, addr = parsed[0]
    return name, addr.lower()


def _collect_raw_headers(msg: Message) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, value in msg.items():
        out.setdefault(key.lower(), []).append(str(value))
    return out


def _extract_attachments(msg: Message) -> list[Attachment]:
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()
        if disposition != "attachment" and not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            Attachment(
                filename=filename,
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return attachments


def _extract_bodies(msg: Message) -> tuple[str, str]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        try:
            payload = part.get_content()
        except Exception:
            raw = part.get_payload(decode=True) or b""
            payload = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/plain" and isinstance(payload, str):
            text_parts.append(payload)
        elif content_type == "text/html" and isinstance(payload, str):
            html_parts.append(payload)
    return "\n".join(text_parts), "\n".join(html_parts)


def parse_eml(source: str | bytes | Path) -> ParsedEmail:
    """Parse an .eml file into a ParsedEmail. `source` is a filesystem path
    (str or Path) or the raw message bytes; a missing path raises
    FileNotFoundError."""
    raw = source if isinstance(source, bytes) else Path(source).read_bytes()

    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_name, from_addr = _first_addr(msg, "From")
    reply_name, reply_addr = _first_addr(msg, "Reply-To")
    _, return_path_addr = _first_addr(msg, "Return-Path")

    date_raw = msg.get("Date")
    try:
        if date_raw:
            parsedate_to_datetime(date_raw)  # validate; keep raw string for display
    except (TypeError, ValueError):
        pass

    body_text, body_html = _extract_bodies(msg)
    if not body_text and body_html:
        body_text = html_to_text(body_html)

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        date_raw=date_raw,
        message_id=msg.get("Message-ID"),
        from_display_name=from_name,
        from_addr=from_addr,
        from_domain=_domain_of(from_addr) or "",
        reply_to_addr=reply_addr or None,
        reply_to_domain=_domain_of(reply_addr),
        return_path_addr=return_path_addr or None,
        return_path_domain=_domain_of(return_path_addr),
        received_headers=[str(v) for v in msg.get_all("Received", [])],
        auth_results_headers=[str(v) for v in msg.get_all("Authentication-Results", [])],
        body_text=body_text,
        body_html=body_html,
        html_links=extract_links(body_html) if body_html else [],
        attachments=_extract_attachments(msg),
        raw_headers=_collect_raw_headers(msg),
    )
