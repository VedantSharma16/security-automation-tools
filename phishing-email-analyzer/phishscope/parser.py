"""Parse a raw RFC 5322 message (.eml) into a structured, analysis-ready object.

Only the standard library ``email`` package is used. Nothing in the message is
ever executed, rendered, or fetched: HTML is treated as text, attachments are
hashed but never written to disk, and URLs are extracted but never resolved.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path


@dataclass
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].lower().strip(">") if "@" in self.address else ""

    def to_dict(self) -> dict:
        return {"display_name": self.display_name, "address": self.address, "domain": self.domain}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    magic: bytes = field(repr=False, default=b"")

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
        }


@dataclass
class ParsedEmail:
    subject: str
    sender: Address
    reply_to: list[Address]
    return_path: str
    to: list[Address]
    date: str
    message_id: str
    headers: list[tuple[str, str]]
    text_body: str
    html_body: str
    attachments: list[Attachment]

    def header_values(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def return_path_domain(self) -> str:
        addr = self.return_path.strip().strip("<>")
        return addr.rpartition("@")[2].lower() if "@" in addr else ""


def _safe_str(value) -> str:
    return "" if value is None else str(value)


def _decode_part(part: EmailMessage) -> str:
    try:
        content = part.get_content()
    except (LookupError, ValueError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        content = payload.decode("utf-8", errors="replace")
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    return content


def _to_address(raw: str) -> Address:
    name, addr = parseaddr(raw)
    return Address(display_name=name.strip(), address=addr.strip().lower())


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        ctype = part.get_content_type()

        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    md5=hashlib.md5(payload).hexdigest(),
                    magic=payload[:8],
                )
            )
        elif ctype == "text/plain":
            text_parts.append(_decode_part(part))
        elif ctype == "text/html":
            html_parts.append(_decode_part(part))

    # Raw header values (not policy-folded objects) so malformed headers survive.
    headers = [(k, _safe_str(v)) for k, v in msg.raw_items()]

    return ParsedEmail(
        subject=_safe_str(msg.get("Subject")),
        sender=_to_address(_safe_str(msg.get("From"))),
        reply_to=[Address(n.strip(), a.lower()) for n, a in getaddresses(msg.get_all("Reply-To", []))],
        return_path=_safe_str(msg.get("Return-Path")),
        to=[Address(n.strip(), a.lower()) for n, a in getaddresses(msg.get_all("To", []))],
        date=_safe_str(msg.get("Date")),
        message_id=_safe_str(msg.get("Message-ID")),
        headers=headers,
        text_body="\n".join(text_parts),
        html_body="\n".join(html_parts),
        attachments=attachments,
    )


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
