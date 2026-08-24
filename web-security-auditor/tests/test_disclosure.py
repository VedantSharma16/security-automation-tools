from webauditor.disclosure import check_robots_txt, check_sensitive_paths, load_sensitive_paths
from webauditor.fetch import FetchResult

PATH_SPECS = [
    {
        "id": "exposed-git-head",
        "path": "/.git/HEAD",
        "severity": "critical",
        "description": "Exposed .git directory.",
    },
    {
        "id": "security-txt-present",
        "path": "/.well-known/security.txt",
        "severity": "info",
        "positive": True,
        "description": "security.txt present.",
    },
]


class FakeFetcher:
    def __init__(self, responses: dict[str, FetchResult]):
        self._responses = responses

    def get(self, url, extra_headers=None):
        for suffix, result in self._responses.items():
            if url.endswith(suffix):
                return result
        return FetchResult(url=url, status_code=404, body="")


def test_exposed_path_flagged():
    fetcher = FakeFetcher(
        {
            "/.git/HEAD": FetchResult(url="x", status_code=200, body="ref: refs/heads/main\n"),
        }
    )
    findings = check_sensitive_paths(fetcher, "https://example.com", PATH_SPECS)
    ids = {f.id for f in findings}
    assert "exposed-git-head" in ids
    finding = next(f for f in findings if f.id == "exposed-git-head")
    assert finding.severity.name == "CRITICAL"
    assert "refs/heads/main" in finding.evidence


def test_404_paths_not_flagged():
    fetcher = FakeFetcher({})
    findings = check_sensitive_paths(fetcher, "https://example.com", PATH_SPECS)
    assert findings == []


def test_empty_200_body_not_flagged():
    fetcher = FakeFetcher({"/.git/HEAD": FetchResult(url="x", status_code=200, body="   ")})
    findings = check_sensitive_paths(fetcher, "https://example.com", PATH_SPECS)
    assert findings == []


def test_positive_finding_has_no_remediation():
    fetcher = FakeFetcher(
        {"/.well-known/security.txt": FetchResult(url="x", status_code=200, body="Contact: mailto:security@example.com")}
    )
    findings = check_sensitive_paths(fetcher, "https://example.com", PATH_SPECS)
    finding = next(f for f in findings if f.id == "security-txt-present")
    assert finding.remediation == ""
    assert finding.title.startswith("Informational:")


def test_robots_txt_flags_interesting_disallow():
    body = "User-agent: *\nDisallow: /admin/\nDisallow: /public/\n"
    fetcher = FakeFetcher({"/robots.txt": FetchResult(url="x", status_code=200, body=body)})
    findings = check_robots_txt(fetcher, "https://example.com")
    assert len(findings) == 1
    assert "/admin/" in findings[0].evidence
    assert "/public/" not in findings[0].evidence


def test_robots_txt_with_no_interesting_entries_not_flagged():
    body = "User-agent: *\nDisallow: /public/\n"
    fetcher = FakeFetcher({"/robots.txt": FetchResult(url="x", status_code=200, body=body)})
    findings = check_robots_txt(fetcher, "https://example.com")
    assert findings == []


def test_missing_robots_txt_not_flagged():
    fetcher = FakeFetcher({})
    findings = check_robots_txt(fetcher, "https://example.com")
    assert findings == []


def test_load_sensitive_paths_default_file_parses():
    specs = load_sensitive_paths()
    assert isinstance(specs, list)
    assert any(spec["id"] == "exposed-git-head" for spec in specs)
    assert all({"id", "path", "severity", "description"} <= spec.keys() for spec in specs)
