"""Parse a raw .eml file into a structured ParsedEmail.

Uses only the standard library `email` package (modern ``policy.default``
API), keeping the tool dependency-free and fully offline, consistent with
the rest of this repo. Link/anchor-text extraction uses simple regexes
rather than an HTML parser dependency -- sufficient for the phishing-link
heuristics this tool needs, without pulling in bs4/lxml.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

_HREF_RE = re.compile(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_BARE_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)]+", re.IGNORECASE)


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int


@dataclass
class Link:
    href: str
    anchor_text: str


@dataclass
class ParsedEmail:
    headers: dict[str, str]
    from_display_name: str
    from_address: str
    reply_to_address: str
    subject: str
    date: str | None
    body_text: str
    body_html: str
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    authentication_results_raw: str | None = None
    received_headers: list[str] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return self.from_address.rsplit("@", 1)[-1].lower() if "@" in self.from_address else ""

    @property
    def reply_to_domain(self) -> str:
        return self.reply_to_address.rsplit("@", 1)[-1].lower() if "@" in self.reply_to_address else ""


def _strip_tags(html_fragment: str) -> str:
    return _TAG_RE.sub("", html_fragment).strip()


def _extract_links(body_html: str, body_text: str) -> list[Link]:
    links: list[Link] = []
    seen: set[tuple[str, str]] = set()

    for href, inner_html in _HREF_RE.findall(body_html):
        text = _strip_tags(inner_html)
        key = (href, text)
        if key not in seen:
            seen.add(key)
            links.append(Link(href=href, anchor_text=text))

    for url in _BARE_URL_RE.findall(body_text):
        key = (url, url)
        if key not in seen:
            seen.add(key)
            links.append(Link(href=url, anchor_text=url))

    return links


def _get_body_text(msg: EmailMessage) -> tuple[str, str]:
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))

    body_text = ""
    body_html = ""
    if text_part is not None:
        body_text = text_part.get_content()
    if html_part is not None:
        body_html = html_part.get_content()

    return body_text, body_html


def parse_bytes(data: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(data)

    headers: dict[str, str] = {}
    for key, value in msg.items():
        headers.setdefault(key, str(value))

    from_display_name, from_address = parseaddr(str(msg.get("From", "")))
    _, reply_to_address = parseaddr(str(msg.get("Reply-To", "")))

    body_text, body_html = _get_body_text(msg)
    links = _extract_links(body_html, body_text)

    attachments: list[Attachment] = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            Attachment(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size=len(payload),
            )
        )

    return ParsedEmail(
        headers=headers,
        from_display_name=from_display_name,
        from_address=from_address,
        reply_to_address=reply_to_address,
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date")) if msg.get("Date") else None,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
        authentication_results_raw=str(msg.get("Authentication-Results"))
        if msg.get("Authentication-Results")
        else None,
        received_headers=[str(v) for v in msg.get_all("Received", [])],
    )


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
