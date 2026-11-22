import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
