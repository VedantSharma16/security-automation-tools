from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def default_rules_path() -> Path:
    return REPO_ROOT / "rules" / "default_rules.yaml"
