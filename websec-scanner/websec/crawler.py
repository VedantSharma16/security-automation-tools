"""A small, same-origin-only crawler used to discover injection-probe targets.

This is deliberately minimal: it follows <a href> links and reads GET <form>
definitions, staying strictly within the scanned host, up to a page/link
budget. It is not a general-purpose spider.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from .models import Endpoint


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlparse(base), urlparse(candidate)
    return (b.scheme, b.netloc) == (c.scheme, c.netloc)


def extract_links(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        absolute = urljoin(base_url, tag["href"])
        if _same_origin(base_url, absolute) and absolute.split("#")[0] not in links:
            links.append(absolute.split("#")[0])
    return links


def extract_get_forms(base_url: str, html: str) -> list[Endpoint]:
    """Return Endpoints for <form method="get"> with their input defaults."""
    soup = BeautifulSoup(html, "html.parser")
    endpoints = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        if method != "get":
            continue
        action = urljoin(base_url, form.get("action") or base_url)
        if not _same_origin(base_url, action):
            continue
        params = {}
        for field in form.find_all(["input", "textarea"]):
            name = field.get("name")
            if not name:
                continue
            params[name] = field.get("value") or "test"
        if params:
            endpoints.append(Endpoint(url=action, params=params, method="GET", source="form"))
    return endpoints


def endpoints_with_query_params(urls: list[str]) -> list[Endpoint]:
    """Turn any crawled URL that already carries query params into an Endpoint."""
    endpoints = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        base = url.split("?")[0]
        endpoints.append(Endpoint(url=base, params=params, method="GET", source="crawl"))
    return endpoints


class Crawler:
    """Breadth-first, same-origin crawl bounded by `max_pages`."""

    def __init__(self, fetch, max_pages: int = 25):
        # `fetch(url) -> (status_code, headers, body)` is injected so the
        # crawler shares the scanner's HTTP session/timeout/user-agent.
        self._fetch = fetch
        self.max_pages = max_pages

    def crawl(self, start_url: str) -> tuple:
        """Returns (visited_pages: list[(url, status, headers, body)], endpoints: list[Endpoint])."""
        seen = {start_url}
        queue = [start_url]
        visited = []
        endpoints: list[Endpoint] = []

        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            status, headers, body = self._fetch(url)
            visited.append((url, status, headers, body))
            if status != 200 or not body:
                continue

            content_type = headers.get("Content-Type", "")
            if content_type and "html" not in content_type:
                continue

            links = extract_links(url, body)
            endpoints.extend(endpoints_with_query_params(links))
            endpoints.extend(extract_get_forms(url, body))

            for link in links:
                if link not in seen and len(seen) < self.max_pages:
                    seen.add(link)
                    queue.append(link)

        # De-duplicate endpoints by (url, sorted param names).
        unique = {}
        for ep in endpoints:
            key = (ep.url, tuple(sorted(ep.params)))
            unique[key] = ep
        return visited, list(unique.values())
