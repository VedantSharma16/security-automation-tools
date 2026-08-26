"""Shared data structures used across the httpsec package."""

from dataclasses import dataclass, field, asdict

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    """A single audit finding."""

    id: str
    category: str  # "headers" | "cookies" | "cors" | "tls"
    severity: str  # one of SEVERITIES
    title: str
    description: str
    remediation: str
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"invalid severity {self.severity!r}, must be one of {SEVERITIES}"
            )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FetchResult:
    """Normalized result of fetching a single URL."""

    url: str
    final_url: str
    status_code: int
    headers: dict
    set_cookies: list = field(default_factory=list)
    redirect_chain: list = field(default_factory=list)
    elapsed_ms: float = 0.0


@dataclass
class TLSInfo:
    """Normalized TLS handshake/certificate data for a host:port."""

    protocol: str
    cipher_name: str
    cipher_bits: int
    not_before: str
    not_after: str
    days_until_expiry: int
    subject_cn: str = ""
    issuer_cn: str = ""
    san: list = field(default_factory=list)
