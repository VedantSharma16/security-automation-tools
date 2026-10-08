"""Parse RFC 5322 messages into a ParsedEmail."""
from __future__ import annotations

import email
import hashlib
import re
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

from .models import Attachment, Link, ParsedEmail

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            if self._href:
                self.links.append(Link(self._href.strip(), " ".join("".join(self._buf).split())))
            self._href = None


def _addr(value: str) -> tuple[str, str]:
    name, addr = parseaddr(str(value or ""))
    return name.strip(), addr.strip().lower()


def parse_auth_results(headers: list[str]) -> dict:
    results: dict[str, str] = {}
    for h in headers:
        for mech, verdict in AUTH_RE.findall(str(h)):
            results.setdefault(mech.lower(), verdict.lower())  # first (top-most) wins
    return results


def parse_message(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=policy.default)
    p = ParsedEmail()
    p.from_name, p.from_addr = _addr(msg.get("From", ""))
    p.reply_to = _addr(msg.get("Reply-To", ""))[1]
    p.return_path = _addr(msg.get("Return-Path", ""))[1]
    p.subject = str(msg.get("Subject", ""))
    p.date = str(msg.get("Date", ""))
    p.message_id = str(msg.get("Message-ID", "")).strip()
    p.auth = parse_auth_results(msg.get_all("Authentication-Results", []))
    p.received = [" ".join(str(r).split()) for r in msg.get_all("Received", [])]

    texts: list[str] = []
    seen: set[tuple[str, str]] = set()

    def add_link(link: Link) -> None:
        key = (link.href, link.text)
        if key not in seen:
            seen.add(key)
            p.links.append(link)

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            p.attachments.append(
                Attachment(filename or "(unnamed)", ctype, len(payload), hashlib.sha256(payload).hexdigest())
            )
        elif ctype == "text/plain":
            body = part.get_content()
            texts.append(body)
            for url in URL_RE.findall(body):
                add_link(Link(url.rstrip(".,;")))
        elif ctype == "text/html":
            ap = _AnchorParser()
            ap.feed(part.get_content())
            texts.append(" ".join("".join(ap.text).split()))
            for link in ap.links:
                add_link(link)
    p.text = "\n".join(texts)
    return p
