"""Parse a raw RFC 5322 message (.eml) into a structured, analysis-ready object.

Only the standard library is used. The parser never executes, renders, or
fetches anything from the message: HTML is tokenized, attachments are hashed
in memory, and URLs are extracted as strings.
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

URL_RE = re.compile(r"""(?i)\b((?:https?|hxxps?)://[^\s<>"'\)\]]+)""")


@dataclass
class Link:
    """A URL found in the message body, with its visible anchor text if from HTML."""

    url: str
    text: str = ""
    source: str = "text"  # "html" or "text"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    head: bytes = field(default=b"", repr=False)  # first bytes, for magic-number checks


@dataclass
class AuthResults:
    """Parsed `Authentication-Results` verdicts (lower-cased), or None if absent."""

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


@dataclass
class ParsedEmail:
    subject: str
    from_display: str
    from_address: str
    reply_to: list[str]
    return_path: str
    to: list[str]
    message_id: str
    date: str
    received: list[str]
    auth: AuthResults
    text_body: str
    html_body: str
    links: list[Link]
    attachments: list[Attachment]
    headers: dict[str, str]

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_address)


def domain_of(address: str) -> str:
    """Return the lower-cased domain part of an email address ('' if none)."""
    _, addr = parseaddr(address or "")
    return addr.rsplit("@", 1)[1].lower().strip(">. ") if "@" in addr else ""


class _AnchorCollector(HTMLParser):
    """Collect <a href> targets with their visible text, plus bare-text URLs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_chunks: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href = attrs["href"].strip()
            self._anchor_text = []
        elif tag == "form" and attrs.get("action"):
            # Credential-harvesting forms embedded directly in the email.
            self.links.append(Link(url=attrs["action"].strip(), text="<form action>", source="html"))

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._anchor_text).split())
            self.links.append(Link(url=self._href, text=text, source="html"))
            self._href = None

    def handle_data(self, data):
        self.text_chunks.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _parse_auth_results(values: list[str]) -> AuthResults:
    """Take the first verdict per mechanism from Authentication-Results headers.

    The top-most header was added by the receiving MTA we trust; later ones may
    have been forged by the sender, so first-seen wins.
    """
    result = AuthResults()
    for value in values:
        for mech in ("spf", "dkim", "dmarc"):
            if getattr(result, mech) is None:
                m = re.search(rf"\b{mech}=([a-z]+)", value, re.IGNORECASE)
                if m:
                    setattr(result, mech, m.group(1).lower())
    return result


def _decode_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _dedupe_links(links: list[Link]) -> list[Link]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for link in links:
        key = (link.url, link.text)
        if key not in seen:
            seen.add(key)
            unique.append(link)
    return unique


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
            data = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    head=data[:8],
                )
            )
        elif ctype == "text/plain":
            text_parts.append(_decode_text(part))
        elif ctype == "text/html":
            html_parts.append(_decode_text(part))

    text_body = "\n".join(text_parts)
    html_body = "\n".join(html_parts)

    links: list[Link] = []
    if html_body:
        collector = _AnchorCollector()
        collector.feed(html_body)
        links.extend(collector.links)
        anchored = {l.url for l in collector.links}
        # URLs that are only the *visible text* of an anchor are not links; the
        # anchor-vs-href comparison in checks.py already covers them.
        anchor_texts = " ".join(l.text for l in collector.links)
        for url in URL_RE.findall(" ".join(collector.text_chunks)):
            if url not in anchored and url not in anchor_texts:
                links.append(Link(url=url, source="html"))
    for url in URL_RE.findall(text_body):
        links.append(Link(url=url, source="text"))

    from_display, from_address = parseaddr(str(msg.get("From", "")))
    rp = parseaddr(str(msg.get("Return-Path", "")))[1]

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_display=from_display,
        from_address=from_address.lower(),
        reply_to=[a.lower() for _, a in getaddresses(msg.get_all("Reply-To", [])) if a],
        return_path=rp.lower(),
        to=[a.lower() for _, a in getaddresses(msg.get_all("To", [])) if a],
        message_id=str(msg.get("Message-ID", "")),
        date=str(msg.get("Date", "")),
        received=[str(v) for v in msg.get_all("Received", [])],
        auth=_parse_auth_results([str(v) for v in msg.get_all("Authentication-Results", [])]),
        text_body=text_body,
        html_body=html_body,
        links=_dedupe_links(links),
        attachments=attachments,
        headers={k: str(v) for k, v in msg.items()},
    )


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
