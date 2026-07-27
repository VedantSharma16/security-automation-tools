import pytest


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    """Keep the test suite fully offline regardless of the host environment."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
