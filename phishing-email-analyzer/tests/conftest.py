from pathlib import Path

import pytest

from phishscope.detectors import build_context, run_all_detectors
from phishscope.parser import parse_bytes, parse_file

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_path():
    return lambda name: FIXTURES / name


@pytest.fixture
def analyze():
    """Analyze a fixture file name or raw bytes; return (ctx, findings, rule-set)."""

    def _analyze(source, **kwargs):
        email = parse_bytes(source) if isinstance(source, bytes) else parse_file(FIXTURES / source)
        ctx = build_context(email, **kwargs)
        findings = run_all_detectors(ctx)
        return ctx, findings, {f.rule for f in findings}

    return _analyze


def _make_eml(headers: dict[str, str] | None = None, body: str = "hello", html: str | None = None) -> bytes:
    base = {
        "From": "Alice <alice@example.org>",
        "To": "bob@corp.example",
        "Subject": "test",
        "Authentication-Results": "mx.corp.example; spf=pass smtp.mailfrom=example.org; "
        "dkim=pass header.d=example.org; dmarc=pass header.from=example.org",
    }
    base.update(headers or {})
    lines = [f"{k}: {v}" for k, v in base.items() if v is not None]
    if html is not None:
        lines += ["MIME-Version: 1.0", 'Content-Type: text/html; charset="utf-8"', "", html]
    else:
        lines += ['Content-Type: text/plain; charset="utf-8"', "", body]
    return "\r\n".join(lines).encode()


@pytest.fixture
def make_eml():
    return _make_eml
