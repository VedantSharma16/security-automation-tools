"""Body analysis: links, forms, hidden text, and urgency / prompt-injection language.

HTML is parsed with the stdlib ``html.parser`` purely as a tokenizer; it is
never rendered. We track which text a human reader would actually *see*
versus text hidden with CSS, because hidden text is used both to evade
content filters and, increasingly, to smuggle instructions to AI email
assistants that summarize or act on the user's inbox.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

_URL_RE = re.compile(r"""\bhttps?://[^\s<>"'()\[\]{}]+""", re.IGNORECASE)
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:;|$)"
    r"|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|max-height\s*:\s*0|"
    r"color\s*:\s*(?:#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)",
    re.IGNORECASE,
)

URGENCY_PATTERNS = [
    r"\burgent(?:ly)?\b", r"\bimmediate(?:ly)?\b", r"\bwithin \d+ hours?\b", r"\bsuspend(?:ed|ion)?\b",
    r"\baccount (?:has been |will be )?(?:locked|disabled|closed|restricted)\b", r"\bverify your (?:account|identity)\b",
    r"\bconfirm your (?:password|credentials|details)\b", r"\bunusual (?:sign-?in|activity)\b",
    r"\bpassword (?:expires|expired|reset)\b", r"\bfinal (?:notice|warning)\b", r"\bact now\b",
    r"\bwire transfer\b", r"\bgift cards?\b", r"\binvoice (?:attached|overdue)\b", r"\bpayment (?:failed|declined)\b",
]

# Phrases aimed at an LLM rather than a human. Attackers hide these in emails so
# that an AI assistant summarizing the inbox follows them (indirect prompt injection).
PROMPT_INJECTION_PATTERNS = [
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above) (?:instructions|prompts?|context)",
    r"disregard (?:all |any )?(?:the )?(?:previous|prior|above|system)",
    r"\byou are (?:now )?(?:an?|the) (?:ai|assistant|language model|helpful)",
    r"\b(?:ai|llm) assistant[s]?\b.{0,40}\b(?:must|should|need to)\b",
    r"\bsystem prompt\b", r"\bnew instructions?:", r"\bdo not (?:tell|inform|mention (?:this )?to) the user\b",
    r"\b(?:forward|send|exfiltrate) (?:all |the )?(?:emails?|messages|contacts|password)",
    r"\bclassify this (?:email|message) as (?:safe|legitimate|benign)\b",
    r"</?(?:system|instructions?|assistant)>",
]


@dataclass
class Link:
    url: str
    text: str = ""
    source: str = "text"  # "html_anchor", "html_text", "text"

    @property
    def host(self) -> str:
        try:
            return (urlsplit(self.url).hostname or "").lower()
        except ValueError:
            return ""

    def to_dict(self) -> dict:
        return {"url": self.url, "text": self.text, "host": self.host, "source": self.source}


@dataclass
class BodyAnalysis:
    links: list[Link] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)
    visible_text: str = ""
    hidden_text: str = ""
    urgency_hits: list[str] = field(default_factory=list)
    injection_hits: list[str] = field(default_factory=list)


class _HTMLScanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.anchors: list[Link] = []
        self.forms: list[str] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self._skip_depth = 0  # inside <script>/<style>/<title>

    def _hidden_now(self) -> bool:
        return any(h for _, h in self.stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style", "title", "head"):
            self._skip_depth += 1
        if tag == "a" and a.get("href"):
            self._anchor_href = a["href"].strip()
            self._anchor_text = []
        if tag == "form":
            self.forms.append(a.get("action", "").strip() or "(same page)")
        if tag not in _VOID_TAGS:
            hidden = bool(_HIDDEN_STYLE_RE.search(a.get("style", ""))) or "hidden" in a
            self.stack.append((tag, hidden))

    def handle_endtag(self, tag):
        if tag in ("script", "style", "title", "head") and self._skip_depth:
            self._skip_depth -= 1
        if tag == "a" and self._anchor_href is not None:
            self.anchors.append(Link(self._anchor_href, " ".join("".join(self._anchor_text).split()), "html_anchor"))
            self._anchor_href = None
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._anchor_href is not None:
            self._anchor_text.append(data)
        (self.hidden if self._hidden_now() else self.visible).append(data)


def _match_all(patterns: list[str], text: str) -> list[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE | re.DOTALL)
        if m:
            hits.append(" ".join(m.group(0).split()))
    return hits


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?'\"")


def analyze_body(text_body: str, html_body: str) -> BodyAnalysis:
    result = BodyAnalysis()
    seen: set[str] = set()

    if html_body:
        scanner = _HTMLScanner()
        scanner.feed(html_body)
        scanner.close()
        for link in scanner.anchors:
            if link.url.lower().startswith(("http://", "https://")) and link.url not in seen:
                seen.add(link.url)
                result.links.append(link)
        result.form_actions = scanner.forms
        result.visible_text = " ".join(" ".join(scanner.visible).split())
        result.hidden_text = " ".join(" ".join(scanner.hidden).split())
        for url in _URL_RE.findall(result.visible_text + " " + result.hidden_text):
            url = _clean_url(url)
            if url not in seen:
                seen.add(url)
                result.links.append(Link(url, source="html_text"))

    for url in _URL_RE.findall(text_body or ""):
        url = _clean_url(url)
        if url not in seen:
            seen.add(url)
            result.links.append(Link(url, source="text"))

    all_text = " ".join(filter(None, [text_body, result.visible_text, result.hidden_text]))
    result.urgency_hits = _match_all(URGENCY_PATTERNS, all_text)
    result.injection_hits = _match_all(PROMPT_INJECTION_PATTERNS, all_text + " " + (html_body or ""))
    return result
