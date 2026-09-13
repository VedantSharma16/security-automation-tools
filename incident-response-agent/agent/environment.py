"""Read-only access to the simulated SOC environment the agent investigates.

Everything here is intentionally side-effect free: the agent can only look,
never touch. Containment/remediation is left as a human decision, informed by
the agent's final recommendation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<program>.+)$"
)


class UnknownHostError(KeyError):
    """Raised when a tool is asked about a host that isn't in the environment."""


@dataclass
class Environment:
    """A snapshot of hosts, processes, log lines, and threat-intel to query."""

    hosts: dict = field(default_factory=dict)
    processes: dict = field(default_factory=dict)
    log_lines: list[str] = field(default_factory=list)
    ioc_feed: dict = field(default_factory=dict)

    @classmethod
    def load(cls, data_dir: Path | str = DEFAULT_DATA_DIR) -> "Environment":
        data_dir = Path(data_dir)
        hosts = json.loads((data_dir / "hosts.json").read_text(encoding="utf-8"))
        processes = json.loads((data_dir / "processes.json").read_text(encoding="utf-8"))
        ioc_feed = json.loads((data_dir / "ioc_feed.json").read_text(encoding="utf-8"))
        log_lines = (data_dir / "auth.log").read_text(encoding="utf-8").splitlines()
        return cls(hosts=hosts, processes=processes, log_lines=log_lines, ioc_feed=ioc_feed)

    def require_host(self, host: str) -> dict:
        if host not in self.hosts:
            raise UnknownHostError(host)
        return self.hosts[host]

    def search_logs(self, host: str, query: str | None = None) -> list[str]:
        """Return log lines for ``host``, optionally filtered to those containing ``query``."""
        self.require_host(host)
        matches = []
        for line in self.log_lines:
            m = _LOG_LINE_RE.match(line)
            if not m or m.group("host") != host:
                continue
            if query and query.lower() not in line.lower():
                continue
            matches.append(line)
        return matches

    def get_process_list(self, host: str) -> list[dict]:
        self.require_host(host)
        return self.processes.get(host, [])

    def get_process_detail(self, host: str, pid: int) -> dict | None:
        self.require_host(host)
        for proc in self.processes.get(host, []):
            if proc["pid"] == pid:
                return proc
        return None

    def lookup_ioc(self, indicator: str) -> dict:
        hit = self.ioc_feed.get(indicator)
        if hit is None:
            return {
                "indicator": indicator,
                "is_known_malicious": False,
                "confidence": "n/a",
                "source": "none",
                "notes": "No match in the local threat-intel feed.",
            }
        return {"indicator": indicator, **hit}
