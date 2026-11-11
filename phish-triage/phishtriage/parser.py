"""Parse an RFC 5322 email (.eml) into a structured, analysis-friendly object.

Only the standard library is used. The parser is deliberately tolerant:
real phishing samples are often malformed, so missing headers become
``None``/empty values instead of exceptions.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

URL_RE = re.compile(r"""\bhttps?://[^\s<>"')\]]+""", re.IGNORECASE)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Link:
    href: str
    text: str
    source: str  # "html" | "text" | "form"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    payload: bytes = field(repr=False)

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
        }


@dataclass
class AuthResults:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None

    def to_dict(self) -> dict:
        return {"spf": self.spf, "dkim": self.dkim, "dmarc": self.dmarc}


@dataclass
class ReceivedHop:
    from_host: str | None
    by_host: str | None
    ip: str | None
    timestamp: str | None


@dataclass
class ParsedEmail:
    subject: str
    from_name: str
    from_address: str
    from_domain: str
    reply_to: str | None
    reply_to_domain: str | None
    return_path: str | None
    return_path_domain: str | None
    to: list[str]
    message_id: str | None
    date: str | None
    auth: AuthResults
    received: list[ReceivedHop]
    text_body: str
    html_body: str
    html_text: str
    hidden_text: str
    links: list[Link]
    attachments: list[Attachment]

    @property
    def visible_text(self) -> str:
        """Plain-text part plus rendered HTML text.

        Both are included because attackers often put a harmless text/plain
        part next to the HTML part that recipients actually see.
        """
        return "\n".join(t for t in (self.text_body.strip(), self.html_text) if t)

    @property
    def originating_ip(self) -> str | None:
        """IP of the earliest (bottom-most) Received hop that recorded one."""
        for hop in reversed(self.received):
            if hop.ip:
                return hop.ip
        return None


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip(">").lower() or None


class _HTMLExtractor(HTMLParser):
    """Collect anchors, form actions, visible text and CSS-hidden text."""

    _HIDDEN_STYLE = re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|$)"
        r"|color\s*:\s*#?(?:fff(?:fff)?|white)\b",
        re.IGNORECASE,
    )
    _VOID = {"br", "img", "hr", "meta", "link", "input", "wbr", "source"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._text: list[str] = []
        self._hidden: list[str] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self._stack: list[bool] = []  # per open element: is it hidden?
        self._skip_depth = 0  # inside <script>/<style>

    @property
    def _in_hidden(self) -> bool:
        return any(self._stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip_depth += 1
        if tag == "a" and a.get("href"):
            self._anchor_href = a["href"].strip()
            self._anchor_text = []
        if tag == "form" and a.get("action"):
            self.links.append(Link(a["action"].strip(), "", "form"))
        if tag not in self._VOID:
            self._stack.append(bool(self._HIDDEN_STYLE.search(a.get("style", ""))))

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        if tag == "a" and self._anchor_href is not None:
            text = " ".join("".join(self._anchor_text).split())
            self.links.append(Link(self._anchor_href, text, "html"))
            self._anchor_href = None
        if tag not in self._VOID and self._stack:
            self._stack.pop()

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._anchor_href is not None:
            self._anchor_text.append(data)
        (self._hidden if self._in_hidden else self._text).append(data)

    @property
    def text(self) -> str:
        return " ".join(" ".join(self._text).split())

    @property
    def hidden(self) -> str:
        return " ".join(" ".join(self._hidden).split())

    @classmethod
    def extract(cls, html: str) -> "_HTMLExtractor":
        parser = cls()
        if html:
            parser.feed(html)
            parser.close()
        return parser


def _parse_received(values: list[str]) -> list[ReceivedHop]:
    hops = []
    for raw in values:
        raw = " ".join(str(raw).split())
        m_from = re.search(r"\bfrom\s+(\S+)", raw, re.IGNORECASE)
        m_by = re.search(r"\bby\s+(\S+)", raw, re.IGNORECASE)
        m_ip = re.search(r"\[(" + IPV4_RE.pattern + r")\]", raw)
        ts = None
        if ";" in raw:
            try:
                ts = parsedate_to_datetime(raw.rsplit(";", 1)[1].strip()).isoformat()
            except (TypeError, ValueError):
                ts = None
        hops.append(
            ReceivedHop(
                from_host=m_from.group(1) if m_from else None,
                by_host=m_by.group(1) if m_by else None,
                ip=m_ip.group(1) if m_ip else None,
                timestamp=ts,
            )
        )
    return hops


def _parse_auth(msg: EmailMessage) -> AuthResults:
    """Use the top-most Authentication-Results header (added by the receiving MTA)."""
    results = AuthResults()
    headers = msg.get_all("Authentication-Results") or []
    if headers:
        for mech, value in AUTH_RE.findall(str(headers[0])):
            mech = mech.lower()
            if getattr(results, mech) is None:
                setattr(results, mech, value.lower())
    if results.spf is None:
        received_spf = msg.get("Received-SPF")
        if received_spf:
            results.spf = str(received_spf).split()[0].lower()
    return results


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    text, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        (text if ctype == "text/plain" else html).append(content)
    return "\n".join(text), "\n".join(html)


def _attachments(msg: EmailMessage) -> list[Attachment]:
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        out.append(
            Attachment(
                filename=filename or "(unnamed)",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                md5=hashlib.md5(payload).hexdigest(),  # noqa: S324 - IOC format, not security
                payload=payload,
            )
        )
    return out


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    from_name, from_address = parseaddr(str(msg.get("From", "")))
    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1] or None
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1] or None
    to = [addr for _, addr in getaddresses([str(v) for v in msg.get_all("To") or []]) if addr]

    text_body, html_body = _bodies(msg)
    html = _HTMLExtractor.extract(html_body)

    links = list(html.links)
    seen = {link.href for link in links}
    for url in URL_RE.findall(text_body):
        url = url.rstrip(".,;:!?")
        if url not in seen:
            links.append(Link(url, "", "text"))
            seen.add(url)

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_name=from_name,
        from_address=from_address.lower(),
        from_domain=_domain_of(from_address) or "",
        reply_to=reply_to.lower() if reply_to else None,
        reply_to_domain=_domain_of(reply_to),
        return_path=return_path.lower() if return_path else None,
        return_path_domain=_domain_of(return_path),
        to=to,
        message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
        date=str(msg.get("Date")) if msg.get("Date") else None,
        auth=_parse_auth(msg),
        received=_parse_received(msg.get_all("Received") or []),
        text_body=text_body,
        html_body=html_body,
        html_text=html.text,
        hidden_text=html.hidden,
        links=links,
        attachments=_attachments(msg),
    )


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
