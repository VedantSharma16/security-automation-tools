"""Parse a raw RFC 5322 message into a ParsedEmail using only the stdlib."""
from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

from .models import Attachment, ParsedEmail, Url

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)  # type: ignore[assignment]
    name, addr = parseaddr(str(msg.get("From", "")))
    p = ParsedEmail(
        from_display=name,
        from_addr=addr.lower(),
        reply_to=parseaddr(str(msg.get("Reply-To", "")))[1].lower(),
        return_path=parseaddr(str(msg.get("Return-Path", "")))[1].lower(),
        subject=str(msg.get("Subject", "")),
        auth_results=" ".join(str(h) for h in msg.get_all("Authentication-Results", [])),
        received_spf=" ".join(str(h) for h in msg.get_all("Received-SPF", [])),
    )

    texts: list[str] = []
    seen: set[str] = set()

    def add_url(href: str, text: str = "") -> None:
        if href.lower().startswith(("http://", "https://")) and (href, text) not in seen:
            seen.add((href, text))  # type: ignore[arg-type]
            p.urls.append(Url(href=href, text=text, host=host_of(href)))

    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        ctype = part.get_content_type()
        if fname:
            payload = part.get_payload(decode=True) or b""
            p.attachments.append(Attachment(fname, ctype, len(payload)))
            continue
        if ctype in ("text/plain", "text/html"):
            content = part.get_content()
            if ctype == "text/html":
                ap = _AnchorParser()
                ap.feed(content)
                for href, text in ap.anchors:
                    add_url(href, text)
                texts.append(" ".join(ap.text))
            else:
                texts.append(content)
                for m in _URL_RE.findall(content):
                    add_url(m.rstrip(".,;"))
    p.body_text = "\n".join(texts)
    return p


def parse_file(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:
        return parse_bytes(fh.read())
