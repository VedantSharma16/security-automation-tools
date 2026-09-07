"""Port-spec parsing and a curated default port list.

The default list favors ports that are both common in real environments and
interesting from a triage perspective (plaintext protocols, exposed
databases, remote-admin surfaces) over an exhaustive top-N list.
"""

from __future__ import annotations

DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9200, 27017,
)


def parse_ports(spec: str) -> list[int]:
    """Parse a comma-separated list of ports and/or ranges, e.g. "22,80,8000-8010"."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"invalid port range: {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    for p in ports:
        if not (0 < p <= 65535):
            raise ValueError(f"port out of range: {p}")
    return sorted(ports)
