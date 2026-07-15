from pathlib import Path

import pytest

from soc_triage.knowledge_base import load_techniques

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture
def techniques():
    return load_techniques(DATA_DIR / "attack_techniques.json")
