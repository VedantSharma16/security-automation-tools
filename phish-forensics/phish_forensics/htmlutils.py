"""Minimal, dependency-free HTML helpers: strip tags to plain text and pull
out (anchor_text, href) pairs so heuristics.py can spot the classic phishing
tell of a link whose visible text names one domain while its href points
somewhere else.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser


@dataclass
class Link:
    text: str
    href: str


class _LinkAndTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_chunks: list[str] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []
        self._skip_depth = 0  # inside <script>/<style>

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip_depth += 1
            return
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href
                self._current_text = []
        if tag in ("br", "p", "div", "tr", "li"):
            self.text_chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "a" and self._current_href is not None:
            self.links.append(Link(text="".join(self._current_text).strip(), href=self._current_href))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._current_href is not None:
            self._current_text.append(data)
        self.text_chunks.append(data)


def html_to_text(html: str) -> str:
    parser = _LinkAndTextExtractor()
    parser.feed(html)
    text = "".join(parser.text_chunks)
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def extract_links(html: str) -> list[Link]:
    parser = _LinkAndTextExtractor()
    parser.feed(html)
    return parser.links
