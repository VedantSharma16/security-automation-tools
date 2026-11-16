"""Parse a raw RFC 5322 message (.eml) into a structured, analysis-friendly form.

Only the Python standard library is used. Nothing in the message is ever
executed, rendered, or fetched: links are extracted as strings and
attachments are hashed in memory, never written to disk.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path

_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")


@dataclass
class Address:
    display_name: str
    email: str

    @property
    def domain(self) -> str:
        return self.email.rpartition("@")[2].lower().strip(">") if "@" in self.email else ""


@dataclass
class Link:
    url: str
    text: str = ""          # visible anchor text (HTML only)
    source: str = "text"    # "html" | "text"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    head: bytes = b""       # first bytes, for magic-number checks


@dataclass
class ReceivedHop:
    raw: str
    from_host: str = ""
    by_host: str = ""
    ip: str = ""


@dataclass
class ParsedEmail:
    subject: str
    sender: Address
    reply_to: list[Address]
    return_path: str
    to: list[Address]
    date: str
    message_id: str
    auth_results: list[str]
    received: list[ReceivedHop]
    text_body: str
    html_body: str
    links: list[Link]
    attachments: list[Attachment]
    headers: dict[str, list[str]] = field(default_factory=dict)

    @property
    def body(self) -> str:
        """Best plain-text view of the body, for keyword analysis."""
        return self.text_body or _strip_html(self.html_body)


class _AnchorCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.forms: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href = attrs["href"].strip()
            self._text = []
        elif tag == "form" and attrs.get("action"):
            self.links.append(Link(url=attrs["action"].strip(), text="<form action>", source="html"))
        elif tag in ("img", "iframe", "script") and attrs.get("src", "").startswith(("http", "//")):
            # Remote content (tracking pixels, embedded frames) is still an outbound IOC.
            self.links.append(Link(url=attrs["src"].strip(), text=f"<{tag} src>", source="html"))

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append(Link(url=self._href, text=text, source="html"))
            self._href = None


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _strip_html(html: str) -> str:
    if not html:
        return ""
    p = _TextExtractor()
    p.feed(html)
    return " ".join(" ".join(p.parts).split())


_URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]]+""")


def extract_text_urls(text: str) -> list[str]:
    urls = []
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?")
        urls.append(u)
    return urls


def _addr(value: str) -> Address:
    name, email = parseaddr(value or "")
    return Address(display_name=name.strip(), email=email.strip().lower())


def _parse_received(value: str) -> ReceivedHop:
    flat = " ".join(value.split())
    hop = ReceivedHop(raw=flat)
    m = re.search(r"\bfrom\s+(\S+)", flat, re.I)
    if m:
        hop.from_host = m.group(1).strip("()[];").lower()
    m = re.search(r"\bby\s+(\S+)", flat, re.I)
    if m:
        hop.by_host = m.group(1).strip("()[];").lower()
    # Prefer the bracketed IP inside the "from" clause (the connecting peer).
    from_clause = flat.split(" by ", 1)[0]
    m = _IP_RE.search(from_clause)
    if m:
        hop.ip = m.group(1)
    return hop


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    headers: dict[str, list[str]] = {}
    for k, v in msg.raw_items():
        headers.setdefault(k.lower(), []).append(str(v))

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and disposition != "inline") or (
            filename and not ctype.startswith("text/")
        ):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
                    head=payload[:8],
                )
            )
            continue
        if ctype == "text/plain":
            text_parts.append(_safe_content(part))
        elif ctype == "text/html":
            html_parts.append(_safe_content(part))

    text_body = "\n".join(text_parts)
    html_body = "\n".join(html_parts)

    links: list[Link] = []
    if html_body:
        collector = _AnchorCollector()
        collector.feed(html_body)
        links.extend(collector.links)
    seen = {l.url for l in links}
    for u in extract_text_urls(text_body):
        if u not in seen:
            links.append(Link(url=u, source="text"))
            seen.add(u)

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        sender=_addr(str(msg.get("From", ""))),
        reply_to=[Address(n.strip(), e.lower()) for n, e in getaddresses(msg.get_all("Reply-To", []))],
        return_path=parseaddr(str(msg.get("Return-Path", "")))[1].lower(),
        to=[Address(n.strip(), e.lower()) for n, e in getaddresses(msg.get_all("To", []))],
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")).strip(),
        auth_results=[str(v) for v in msg.get_all("Authentication-Results", [])],
        received=[_parse_received(str(v)) for v in msg.get_all("Received", [])],
        text_body=text_body,
        html_body=html_body,
        links=links,
        attachments=attachments,
        headers=headers,
    )


def _safe_content(part) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
