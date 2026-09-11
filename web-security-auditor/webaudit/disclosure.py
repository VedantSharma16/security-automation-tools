"""Information-disclosure checks: version banners and commonly-exposed paths."""

from __future__ import annotations

from .models import CheckResult

_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

# path -> human title. A 200 response for one of these suggests the file is
# being served rather than blocked/404'd — worth a look during an authorized
# assessment, though not proof of a real exposure without inspecting content.
SENSITIVE_PATHS = {
    "/.git/HEAD": "Git repository metadata",
    "/.env": "Environment/config file",
    "/.aws/credentials": "AWS credentials file",
    "/wp-config.php.bak": "WordPress config backup",
    "/.well-known/security.txt": "security.txt (informational, not a risk)",
}


def analyze_banners(headers: dict) -> list[CheckResult]:
    results = []
    for header in _BANNER_HEADERS:
        value = headers.get(header)
        if value:
            results.append(CheckResult(
                f"banner:{header}", "disclosure", "warn", "low",
                f"'{header}' header reveals version info",
                f"{header}: {value}",
                "Suppress or generic-ize version-revealing response headers.",
            ))
    if not results:
        results.append(CheckResult("banner", "disclosure", "pass", "info",
                                    "Server banner", "No version-revealing headers found.", None))
    return results


def analyze_probed_paths(probe_statuses: dict[str, int]) -> list[CheckResult]:
    results = []
    for path, status in probe_statuses.items():
        title = SENSITIVE_PATHS.get(path, path)

        if path == "/.well-known/security.txt":
            status_note = "is published" if status == 200 else "was not found"
            results.append(CheckResult(f"path:{path}", "disclosure", "pass", "info", title,
                                        f"security.txt {status_note} (informational only).", None))
            continue

        if status == 200:
            results.append(CheckResult(
                f"path:{path}", "disclosure", "fail", "high", title,
                f"{path} returned HTTP 200 — {title} may be publicly exposed.",
                "Remove the file from the web root or block it at the web server/proxy.",
            ))
        else:
            results.append(CheckResult(f"path:{path}", "disclosure", "pass", "info", title,
                                        f"{path} is not exposed (HTTP {status}).", None))
    return results
