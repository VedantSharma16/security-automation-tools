"""Parse a raw RFC 5322 message (.eml) into a structured, analysis-ready form.

Only the standard library ``email`` package is used. The parser never
executes or renders anything: HTML is tokenised with ``html.parser`` purely to
pull out links, and attachments are hashed and sniffed by magic bytes, never
written to disk.
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

_URL_RE = re.compile(r"""\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+""", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)]}'\""


@dataclass
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rsplit("@", 1)[-1].lower() if "@" in self.address else ""


@dataclass
class Link:
    url: str
    anchor_text: str = ""
    source: str = "text"  # "html" | "text"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    head: bytes = field(repr=False, default=b"")
    text_sample: str = field(repr=False, default="")


@dataclass
class AuthResults:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    raw: list[str] = field(default_factory=list)


@dataclass
class ParsedEmail:
    subject: str
    message_id: str
    date: str
    from_: Address
    reply_to: list[Address]
    return_path: str
    to: list[Address]
    received: list[str]
    auth: AuthResults
    text_body: str
    html_body: str
    links: list[Link]
    attachments: list[Attachment]
    headers: dict[str, str]

    @property
    def body_text(self) -> str:
        """Plain text for content heuristics; falls back to tag-stripped HTML."""
        if self.text_body.strip():
            return self.text_body
        return _strip_tags(self.html_body)


class _LinkExtractor(HTMLParser):
    """Collect <a href> targets with their visible anchor text, plus form actions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href = attrs["href"].strip()
            self._text = []
        elif tag == "form" and attrs.get("action"):
            self.links.append(Link(attrs["action"].strip(), "<form action>", "html"))

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append(Link(self._href, text, "html"))
            self._href = None


def _strip_tags(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return " ".join(text.split())


def parse_auth_results(values: list[str]) -> AuthResults:
    """Parse Authentication-Results headers (RFC 8601) for spf/dkim/dmarc verdicts.

    When several headers are present, the first (topmost, i.e. added by the
    receiving MTA closest to the mailbox) result for each method wins.
    """
    result = AuthResults(raw=list(values))
    for value in values:
        for method in ("spf", "dkim", "dmarc"):
            if getattr(result, method) is None:
                m = re.search(rf"\b{method}\s*=\s*([a-z]+)", value, re.IGNORECASE)
                if m:
                    setattr(result, method, m.group(1).lower())
    return result


def extract_text_urls(text: str) -> list[str]:
    urls = []
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(_TRAILING_PUNCT)
        if url.lower().startswith("www."):
            url = "http://" + url
        urls.append(url)
    return urls


def _to_address(name: str, addr: str) -> Address:
    return Address(display_name=name.strip(), address=addr.strip().lower())


def _payload_bytes(part: EmailMessage) -> bytes:
    data = part.get_payload(decode=True)
    return data if isinstance(data, bytes) else b""


def parse_message(msg: EmailMessage) -> ParsedEmail:
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
            filename and ctype not in ("text/plain", "text/html")
        ):
            data = _payload_bytes(part)
            sample = ""
            if ctype.startswith("text/") or (filename or "").lower().endswith((".htm", ".html", ".svg")):
                sample = data[:20000].decode("utf-8", errors="replace")
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    md5=hashlib.md5(data).hexdigest(),  # noqa: S324 - IOC format, not security use
                    head=data[:16],
                    text_sample=sample,
                )
            )
        elif ctype == "text/plain":
            text_parts.append(part.get_content())
        elif ctype == "text/html":
            html_parts.append(part.get_content())

    text_body = "\n".join(text_parts)
    html_body = "\n".join(html_parts)

    links: list[Link] = []
    if html_body:
        extractor = _LinkExtractor()
        extractor.feed(html_body)
        links.extend(extractor.links)
    seen = {link.url for link in links}
    for url in extract_text_urls(text_body):
        if url not in seen:
            links.append(Link(url, "", "text"))
            seen.add(url)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_to = [_to_address(n, a) for n, a in getaddresses(msg.get_all("Reply-To", [])) if a]
    to = [_to_address(n, a) for n, a in getaddresses(msg.get_all("To", [])) if a]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()

    headers = {k: str(v) for k, v in msg.items()}
    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        message_id=str(msg.get("Message-ID", "")),
        date=str(msg.get("Date", "")),
        from_=_to_address(from_name, from_addr),
        reply_to=reply_to,
        return_path=return_path,
        to=to,
        received=[str(v) for v in msg.get_all("Received", [])],
        auth=parse_auth_results([str(v) for v in msg.get_all("Authentication-Results", [])]),
        text_body=text_body,
        html_body=html_body,
        links=links,
        attachments=attachments,
        headers=headers,
    )


def parse_bytes(raw: bytes) -> ParsedEmail:
    return parse_message(BytesParser(policy=policy.default).parsebytes(raw))


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
