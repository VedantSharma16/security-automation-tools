"""Parse a raw RFC 5322 message into the pieces the analyzers need."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
HREF_RE = re.compile(r"""<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
                     re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class Link:
    href: str
    text: str = ""  # visible anchor text (HTML only)


@dataclass
class ParsedEmail:
    from_name: str
    from_addr: str
    reply_to: str
    return_path: str
    subject: str
    auth_results: str
    received: list[str]
    text: str
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def addr_domain(addr: str) -> str:
    return _domain(addr)


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))

    plain, html = [], []
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        ctype = part.get_content_type()
        if fname:
            payload = part.get_payload(decode=True) or b""
            attachments.append(Attachment(str(fname), ctype, len(payload)))
        elif ctype == "text/plain":
            plain.append(part.get_content())
        elif ctype == "text/html":
            html.append(part.get_content())

    links: list[Link] = []
    for body in html:
        for href, inner in HREF_RE.findall(body):
            links.append(Link(href.strip(), TAG_RE.sub("", inner).strip()))
    seen = {l.href for l in links}
    for body in plain + html:
        for url in URL_RE.findall(body):
            if url not in seen:
                seen.add(url)
                links.append(Link(url))

    text = "\n".join(plain) or TAG_RE.sub(" ", "\n".join(html))
    return ParsedEmail(
        from_name=name, from_addr=addr.lower(), reply_to=reply_to.lower(),
        return_path=return_path.lower(), subject=str(msg.get("Subject", "")),
        auth_results=" ".join(str(h) for h in msg.get_all("Authentication-Results", [])),
        received=[str(h) for h in msg.get_all("Received", [])],
        text=text, links=links, attachments=attachments,
    )
