import pytest

from llm_redteam.models import Scenario


@pytest.fixture
def scenario():
    return Scenario(canary="CANARY-ABCDEF123456", marker="PWNED-0011AABBCCDD")
