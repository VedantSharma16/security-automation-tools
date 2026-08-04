"""Parse a raw .eml file into a structured, analysis-friendly form.

Uses only the standard library `email` package (with the modern `policy.default`,
which handles MIME decoding, charset detection, and header unfolding for us) plus
`html.parser` for lightweight anchor-tag extraction -- no third-party dependency
like BeautifulSoup is needed for the shallow parsing this tool does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)


@dataclass(frozen=True)
class EmailLink:
    """A URL found in the email, plus whatever text a reader would see for it."""

    href: str
    display_text: str
    source: str  # "text" or "html"


@dataclass(frozen=True)
class Attachment:
    filename: str | None
    content_type: str
    size_bytes: int


@dataclass(frozen=True)
class ParsedEmail:
    from_display: str
    from_addr: str
    from_domain: str
    reply_to_addr: str | None
    reply_to_domain: str | None
    to_addrs: tuple[str, ...]
    subject: str
    date: str | None
    message_id: str | None
    return_path: str | None
    received_count: int
    authentication_results_raw: tuple[str, ...]
    body_text: str
    body_html: str
    links: tuple[EmailLink, ...]
    attachments: tuple[Attachment, ...]

    @property
    def visible_text(self) -> str:
        """All human-readable text in the email: subject + plain body + stripped HTML."""
        parts = [self.subject, self.body_text]
        if self.body_html:
            parts.append(_strip_html(self.body_html))
        return "\n".join(p for p in parts if p)


class _AnchorTextExtractor(HTMLParser):
    """Collects (href, visible text) pairs for every <a href=...>...</a> in an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = next((v for k, v in attrs if k.lower() == "href" and v), None)
        if href:
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []


class _TextStripper(HTMLParser):
    """Reduces an HTML document to its visible text, joined by single spaces."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if stripped:
            self._chunks.append(stripped)

    def text(self) -> str:
        return " ".join(self._chunks)


def _strip_html(html: str) -> str:
    stripper = _TextStripper()
    try:
        stripper.feed(html)
    except Exception:
        return ""
    return stripper.text()


def _extract_html_links(html: str) -> list[tuple[str, str]]:
    extractor = _AnchorTextExtractor()
    try:
        extractor.feed(html)
    except Exception:
        return []
    return extractor.links


def _split_addr(raw: str | None) -> tuple[str, str, str]:
    """Return (display_name, address, domain) for a raw address header value."""
    if not raw:
        return "", "", ""
    display, addr = parseaddr(raw)
    domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
    return display, addr.lower(), domain


def _leaf_parts(msg: EmailMessage):
    for part in msg.walk():
        if not part.is_multipart():
            yield part


def _get_text(part: EmailMessage) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")


def parse_email_bytes(data: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return _parse_message(msg)


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_email_bytes(Path(path).read_bytes())


def _parse_message(msg: EmailMessage) -> ParsedEmail:
    from_display, from_addr, from_domain = _split_addr(msg.get("From"))
    _, reply_addr, reply_domain = _split_addr(msg.get("Reply-To"))

    to_raw = msg.get_all("To", [])
    to_addrs = tuple(
        addr for addr in (_split_addr(r)[1] for r in to_raw) if addr
    )

    auth_headers = tuple(str(h) for h in msg.get_all("Authentication-Results", []))
    received_count = len(msg.get_all("Received", []))

    body_text_chunks: list[str] = []
    body_html_chunks: list[str] = []
    attachments: list[Attachment] = []

    for part in _leaf_parts(msg):
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        is_attachment = disposition == "attachment" or (
            filename is not None and content_type not in ("text/plain", "text/html")
        )

        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=len(payload),
                )
            )
            continue

        if content_type == "text/plain":
            body_text_chunks.append(_get_text(part))
        elif content_type == "text/html":
            body_html_chunks.append(_get_text(part))

    body_text = "\n".join(c for c in body_text_chunks if c)
    body_html = "\n".join(c for c in body_html_chunks if c)

    links: list[EmailLink] = []
    seen: set[tuple[str, str]] = set()

    for href, text in _extract_html_links(body_html):
        if href.lower().startswith(("http://", "https://")):
            key = (href, "html")
            if key not in seen:
                seen.add(key)
                links.append(EmailLink(href=href, display_text=text or href, source="html"))

    for match in _URL_RE.findall(body_text):
        url = match.rstrip(".,;:!?")
        key = (url, "text")
        if key not in seen:
            seen.add(key)
            links.append(EmailLink(href=url, display_text=url, source="text"))

    return ParsedEmail(
        from_display=from_display,
        from_addr=from_addr,
        from_domain=from_domain,
        reply_to_addr=reply_addr or None,
        reply_to_domain=reply_domain or None,
        to_addrs=to_addrs,
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date")) if msg.get("Date") else None,
        message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
        return_path=str(msg.get("Return-Path")) if msg.get("Return-Path") else None,
        received_count=received_count,
        authentication_results_raw=auth_headers,
        body_text=body_text,
        body_html=body_html,
        links=tuple(links),
        attachments=tuple(attachments),
    )
